#!/usr/bin/env python3
"""
Reads app-sources/gitea/server/gitea/templates/swagger/v1_json.tmpl - a fully
generated Swagger 2.0 spec checked into the Gitea repo (built by
`make generate-swagger` from `//swagger:...` doc comments, kept in sync by
CI's `make swagger-check`) - and writes gitea-api-extracted.json: every
REST API v1 operation's method/path/path-params/query-params/body-schema,
with $refs resolved.

One gap the swagger spec itself doesn't fill: it carries types and
required-ness but usually not length/enum bounds (e.g. CreateIssueOption's
`title` is `type: string`, required, no maxLength). Those bounds exist as
Go struct tags (`binding:"MaxSize(255)"` etc.) in the real source, so this
script cross-references every definition's `x-go-package`/property's
`x-go-name` back to the actual struct field in Go source (scoped to just
the packages the spec references: modules/structs, services/forms,
models/activities, modules/timeutil - confirmed via a direct scan, not
assumed) and attaches an `x-binding` tag wherever one exists. Mirrors
mediawiki's paraminfo-is-necessary-but-not-sufficient cross-reference
against dynamic_type_expr.

Usage: python3 extract_swagger.py
"""
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root  # noqa: E402

REPO_ROOT = find_repo_root(SCRIPT_DIR)
GITEA_ROOT = os.path.join(REPO_ROOT, "app-sources", "gitea", "server", "gitea")
SWAGGER_PATH = os.path.join(GITEA_ROOT, "templates", "swagger", "v1_json.tmpl")
OUT_PATH = os.path.join(SCRIPT_DIR, "gitea-api-extracted.json")

GO_MODULE = "gitea.dev"


def load_swagger():
    raw = open(SWAGGER_PATH, encoding="utf-8").read()
    # Exactly two template substitution points in the whole file (confirmed
    # by inspection) - safe to strip with fixed strings instead of pulling
    # in a real Go-template engine.
    raw = raw.replace("{{.SwaggerAppVer}}", "0.0.0")
    raw = raw.replace("{{.SwaggerAppSubUrl}}", "")
    return json.loads(raw)


# --- $ref resolution --------------------------------------------------------

def resolve_ref(spec, ref):
    assert ref.startswith("#/"), ref
    node = spec
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def resolve_schema(spec, schema, seen=None):
    """Recursively resolves $ref/properties/items/allOf into a plain nested
    dict. `seen` (definition names already being expanded on the current
    path) guards against self/mutually-referential definitions (e.g. a
    tree-shaped type) looping forever - a repeat collapses to a generic
    object stub instead. Every resolved $ref gets an `x-def-name` stamped
    on it (in addition to whatever `x-go-package` the definition itself
    carries) so a later pass can re-attach binding info at any depth, not
    just the top level."""
    if seen is None:
        seen = set()
    if not isinstance(schema, dict):
        return schema

    if "$ref" in schema:
        ref = schema["$ref"]
        def_name = ref.rsplit("/", 1)[-1]
        if def_name in seen:
            return {"type": "object", "x-recursive": True}
        target = resolve_ref(spec, ref)
        resolved = resolve_schema(spec, target, seen | {def_name})
        if isinstance(resolved, dict):
            resolved = dict(resolved)
            resolved["x-def-name"] = def_name
        return resolved

    out = dict(schema)
    if "properties" in schema:
        out["properties"] = {
            k: resolve_schema(spec, v, seen) for k, v in schema["properties"].items()
        }
    if "items" in schema:
        out["items"] = resolve_schema(spec, schema["items"], seen)
    if "allOf" in schema:
        # go-swagger emits allOf for embedded/extended structs; merge shallowly.
        merged_props = {}
        required = list(schema.get("required", []))
        for sub in schema["allOf"]:
            rsub = resolve_schema(spec, sub, seen)
            merged_props.update(rsub.get("properties", {}))
            required.extend(rsub.get("required", []))
        out["type"] = "object"
        out["properties"] = merged_props
        if required:
            out["required"] = sorted(set(required))
        out.pop("allOf", None)
    return out


# --- Go struct / binding-tag cross-reference --------------------------------

FIELD_RE = re.compile(
    r'^\s*(?P<name>[A-Z]\w*)\s+(?:\*)?[\[\]A-Za-z0-9_.]+\s*'
    r'`(?P<tag>[^`]*)`\s*(?://.*)?$'
)
TAG_ITEM_RE = re.compile(r'(\w+):"([^"]*)"')
TYPE_STRUCT_RE = re.compile(r'^type\s+(\w+)\s+struct\s*\{\s*$')


def parse_go_structs(go_file_text):
    """Returns {struct_name: {go_field_name: {'json': ..., 'binding': ...}}}
    for every `type X struct { ... }` block in one Go source file.
    Brace-depth walking (not one regex over the whole block) so nested
    braces in a field's type (map[string]struct{...}, embedded structs)
    don't break extraction."""
    structs = {}
    lines = go_file_text.splitlines()
    i = 0
    while i < len(lines):
        m = TYPE_STRUCT_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = 1
        body = []
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            if depth > 0:
                body.append(lines[i])
            i += 1
        fields = {}
        for line in body:
            fm = FIELD_RE.match(line)
            if not fm:
                continue
            tag_items = dict(TAG_ITEM_RE.findall(fm.group("tag")))
            fields[fm.group("name")] = {
                "json": tag_items.get("json", "").split(",")[0],
                "binding": tag_items.get("binding", ""),
            }
        structs[name] = fields
    return structs


def build_binding_index(packages):
    """packages: iterable of 'gitea.dev/x/y' package paths referenced by the
    swagger spec's x-go-package. Returns {(package, struct_name): {field: {...}}}."""
    index = {}
    for pkg in sorted(packages):
        assert pkg.startswith(GO_MODULE + "/"), pkg
        rel = pkg[len(GO_MODULE) + 1:]
        pkg_dir = os.path.join(GITEA_ROOT, rel)
        if not os.path.isdir(pkg_dir):
            continue
        for fname in sorted(os.listdir(pkg_dir)):
            if not fname.endswith(".go") or fname.endswith("_test.go"):
                continue
            text = open(os.path.join(pkg_dir, fname), encoding="utf-8").read()
            for struct_name, fields in parse_go_structs(text).items():
                index[(pkg, struct_name)] = fields
    return index


def annotate_binding_deep(schema, binding_index):
    """Walks a resolved schema tree, attaching x-binding onto any property
    whose enclosing object has both x-def-name and x-go-package matched in
    binding_index (works at any nesting depth, not just the top level)."""
    if not isinstance(schema, dict):
        return
    def_name = schema.get("x-def-name")
    pkg = schema.get("x-go-package")
    fields = binding_index.get((pkg, def_name)) if def_name and pkg else None
    for prop in schema.get("properties", {}).values():
        if fields:
            go_name = prop.get("x-go-name")
            if go_name and go_name in fields and fields[go_name]["binding"]:
                prop["x-binding"] = fields[go_name]["binding"]
        annotate_binding_deep(prop, binding_index)
    if "items" in schema:
        annotate_binding_deep(schema["items"], binding_index)


# --- Operation extraction ---------------------------------------------------

def extract_operations(spec, binding_index):
    ops = []
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            if method not in ("get", "post", "put", "delete", "patch", "head", "options"):
                continue
            path_params = []
            query_params = []
            body_schema = None
            for param in op.get("parameters", []):
                loc = param.get("in")
                if loc == "path":
                    path_params.append({
                        "name": param["name"],
                        "type": param.get("type", "string"),
                    })
                elif loc == "query":
                    query_params.append({
                        "name": param["name"],
                        "type": param.get("type", "string"),
                        "format": param.get("format", ""),
                    })
                elif loc == "body":
                    resolved = resolve_schema(spec, param.get("schema", {}))
                    annotate_binding_deep(resolved, binding_index)
                    body_schema = resolved
            ops.append({
                "method": method,
                "path": path,
                "operation_id": op.get("operationId", ""),
                "path_params": path_params,
                "query_params": query_params,
                "body_schema": body_schema,
            })
    return ops


def main():
    spec = load_swagger()
    packages = {
        defn.get("x-go-package")
        for defn in spec["definitions"].values()
        if defn.get("x-go-package")
    }
    binding_index = build_binding_index(packages)
    ops = extract_operations(spec, binding_index)

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"operations": ops}, f, indent=2, sort_keys=True)

    with_body = sum(1 for o in ops if o["body_schema"])
    print(
        f"Wrote {OUT_PATH}: {len(ops)} operations ({with_body} with a body "
        f"schema), binding index covers {len(binding_index)} structs across "
        f"{len(packages)} packages"
    )


if __name__ == "__main__":
    main()

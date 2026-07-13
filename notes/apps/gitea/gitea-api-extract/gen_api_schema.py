#!/usr/bin/env python3
"""
Generates rootfs/etc/openresty/waf/apps/gitea/api_schema.lua from
gitea-api-extracted.json (extract_swagger.py's output - see that file's
header for where the data comes from).

One route per (method, swagger path) - Gitea's REST API doesn't have
MediaWiki's api.php?action=X funnel problem, so there's no cross-action
union/narrowing step needed here: each operation gets its own independent
`app.routes` entry with its own precise query/body schema.

Two kinds of "don't fully trust the source" gaps, both handled with a
pragmatic bounded-generic fallback rather than an attempt at byte-perfect
reimplementation of Gitea's own validation (that's Gitea's job - the WAF
just needs a reasonable bound, refined later via log-mode traffic like
every other app in this project):
  - Body/query fields with no `x-binding` tag at all (the bare swagger type
    is all we have) get a generic bounded string/number instead of being
    treated as unconstrained.
  - Path parameters and binding rules that resolve to "real Go logic, not a
    simple pattern" (GitRefName, GlobPattern, ValidUrl, ...) get a bounded
    printable-character fallback instead of a precise reimplementation.

Usage: python3 gen_api_schema.py
"""
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root, lua_str, field_key as lua_field_key  # noqa: E402

REPO_ROOT = find_repo_root(SCRIPT_DIR)
IN_PATH = os.path.join(SCRIPT_DIR, "gitea-api-extracted.json")
OUT_PATH = os.path.join(
    REPO_ROOT, "rootfs", "etc", "openresty", "waf", "apps", "gitea", "api_schema.lua"
)

SHORT_STRING_MAX = 1024
LONG_STRING_MAX = 65536
QUERY_STRING_MAX = 512
# Practically-unbounded but not literally infinite (Gitea IDs/indices/counts
# come nowhere near this) - deliberately well clear of 2^53, the largest
# integer a double can represent exactly: cjson round-trips a number this
# size through scientific-notation JSON text, and the boundary test values
# the offline suite generates (max-1, max) landed close enough to 2^53 to
# get rounded across the declared max on the way back through, causing
# spurious denials of otherwise-valid values. INT32_MAX has real precedent
# too - plenty of git-forge DB schemas use 32-bit int columns for these.
NUMBER_MAX = 2147483647

LONG_TEXT_FIELD_HINTS = (
    "body", "content", "description", "message", "comment", "text", "readme",
    "note", "payload",
)

# --- path-parameter -> regex fragment ---------------------------------------
# Keyed by exact swagger parameter name (41 distinct names confirmed across
# all 482 operations before writing this table - not guessed blindly).

NUMERIC_PATH_PARAMS = {
    "id", "index", "runner_id", "attachment_id", "workflow_id",
    "artifact_id", "job_id", "attempt", "position", "task",
}
HEX_PATH_PARAMS = {"sha", "base", "head"}
# Gitea's own `Username` binding rule pattern (modules/validation/helpers.go):
# ^[\da-zA-Z][-.\w]*$ and NOT [-._]{2,}|[-._]$ - applied to every
# name/slug-shaped path segment, not just literal usernames.
NAME_PATH_PARAMS = {
    "owner", "repo", "org", "username", "name", "collaborator", "assignee",
    "user", "team", "template_owner", "template_repo", "repo_name",
    "secretname", "variablename", "tag", "topic", "token", "run", "type",
    "diffType", "pageName", "version", "target",
}
# Can legitimately contain '/' (branch/ref names, file paths, base...head
# compare syntax) - bounded printable-char fallback, not a real git-ref
# validator.
SLASHY_PATH_PARAMS = {"branch", "ref", "filepath", "archive", "basehead"}


def path_param_fragment(name, unrecognized):
    if name in NUMERIC_PATH_PARAMS:
        return r"[0-9]+"
    if name in HEX_PATH_PARAMS:
        return r"[0-9a-fA-F]{4,64}"
    if name in NAME_PATH_PARAMS:
        return r"[\da-zA-Z][-.\w]{0,99}"
    if name in SLASHY_PATH_PARAMS:
        return r"[^?#\x00-\x1f]{1,512}"
    unrecognized.add(name)
    return r"[^?#\x00-\x1f]{1,255}"


def escape_path_literal(s):
    """Static swagger path segments are plain identifiers (word chars, '-',
    '_', '.', '/' - confirmed directly by scanning every path in the spec,
    not assumed). Only '.' is an actual PCRE metacharacter among those, so
    escape just that instead of re.escape() - which, on Python 3.7+, also
    escapes '-' even though it's not special outside a character class,
    something test/gen.lua's path-reversal heuristic doesn't know how to
    undo when building a test URI back out of the route's regex."""
    return s.replace(".", "\\.")


def build_path_regex(path_template, path_params, unrecognized):
    frag_by_name = {p["name"]: path_param_fragment(p["name"], unrecognized) for p in path_params}
    parts = re.split(r"(\{[^}]+\})", path_template)
    out = []
    for part in parts:
        m = re.match(r"^\{([^}]+)\}$", part)
        if m:
            out.append(frag_by_name[m.group(1)])
        else:
            out.append(escape_path_literal(part))
    return "^/api/v1" + "".join(out) + "$"


# --- binding-tag parsing -----------------------------------------------------

def parse_binding(binding_str):
    """'Required;AlphaDashDot;MaxSize(100)' -> [('Required', None), ...]."""
    rules = []
    for part in binding_str.split(";"):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(\w+)(?:\(([^)]*)\))?$", part)
        if m:
            rules.append((m.group(1), m.group(2)))
    return rules


# --- swagger property -> T.* Lua expression ---------------------------------

def string_validator_lua(prop, field_name, rules_by_name):
    opts = []
    max_size = rules_by_name.get("MaxSize")
    min_size = rules_by_name.get("MinSize")
    in_rule = rules_by_name.get("In")
    is_username = "Username" in rules_by_name
    is_email = "Email" in rules_by_name

    if is_email:
        return "T.email()"

    if in_rule is not None:
        values = [v.strip() for v in in_rule.split(",") if v.strip()]
        enum_lua = ", ".join(f"{lua_field_key(v)}=true" for v in values)
        opts.append(f"enum={{ {enum_lua} }}")

    if is_username:
        opts.append(r"match=[[^[0-9a-zA-Z][-.\w]*$]]")
        opts.append(r"not_match=[[[-._]{2,}|[-._]$]]")

    if max_size is not None:
        opts.append(f"max={max_size}")
    elif min_size is None and in_rule is None and not is_username:
        # No length info at all from the Go source - fall back to a
        # generic bound sized by whether the field name looks like free
        # text (body/description/...) or a short identifier-ish field.
        default_max = LONG_STRING_MAX if any(
            hint in field_name.lower() for hint in LONG_TEXT_FIELD_HINTS
        ) else SHORT_STRING_MAX
        opts.append(f"max={default_max}")

    if min_size is not None:
        opts.append(f"min={min_size}")

    return "T.string({ " + ", ".join(opts) + " })" if opts else "T.string({})"


def number_validator_lua(prop, rules_by_name, query=False):
    fmt = prop.get("format", "")
    integer = fmt in ("int32", "int64") or prop.get("type") == "integer"
    opts = ["integer=true"] if integer else []
    range_rule = rules_by_name.get("Range")
    if range_rule:
        lo, hi = [x.strip() for x in range_rule.split(",")]
        opts.append(f"min={lo}")
        opts.append(f"max={hi}")
    else:
        opts.append(f"max={NUMBER_MAX}")
    factory = "T.number_query" if query else "T.number"
    return f"{factory}({{ " + ", ".join(opts) + " })"


def emit_validator(prop, field_name="", query=False):
    """Returns a Lua expression string for one property/query-param."""
    binding = prop.get("x-binding", "")
    rules = parse_binding(binding)
    rules_by_name = {name: val for name, val in rules}
    ptype = prop.get("type", "string")
    fmt = prop.get("format", "")

    if ptype == "boolean":
        return "T.bool_query()" if query else "T.boolean()"
    if ptype == "integer" or ptype == "number":
        return number_validator_lua(prop, rules_by_name, query=query)
    if ptype == "string":
        if fmt == "date-time":
            return "T.iso8601()"
        if query:
            max_size = rules_by_name.get("MaxSize", QUERY_STRING_MAX)
            return f"T.string({{ max={max_size} }})"
        return string_validator_lua(prop, field_name, rules_by_name)
    if ptype == "array":
        items = prop.get("items", {}) or {}
        inner = emit_validator(items, field_name=field_name)
        max_size = rules_by_name.get("MaxSize")
        opts = f", {{ max={max_size} }}" if max_size else ""
        return f"T.array({inner}{opts})"
    if ptype == "object":
        return object_schema_lua(prop)
    # unspecified/unknown type - bounded generic fallback
    return f"T.string({{ max={SHORT_STRING_MAX} }})"


def object_schema_lua(schema, indent="    "):
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    lines = ["T.object({"]
    for name, prop in sorted(props.items()):
        validator = emit_validator(prop, field_name=name)
        lines.append(f"{indent}  {lua_field_key(name)} = {validator},")
    lines.append(f"{indent}}}" + (
        f", {{ required = {{ " + ", ".join(f"{lua_field_key(n)}=true" for n in sorted(required)) + " } }"
        if required else ""
    ) + ")")
    return "\n".join(lines)


# --- route emission -----------------------------------------------------------

def route_lua(op, unrecognized):
    method = op["method"].upper()
    path_regex = build_path_regex(op["path"], op["path_params"], unrecognized)
    name = f"gitea api {method} {op['path']}"

    lines = []
    lines.append("  {")
    lines.append(f"    name = {lua_str(name)},")
    lines.append(f"    method = {lua_str(method)},")
    lines.append(f"    path = {lua_str(path_regex)},")

    if op["query_params"]:
        lines.append("    query = T.object({")
        for p in sorted(op["query_params"], key=lambda p: p["name"]):
            validator = emit_validator(p, field_name=p["name"], query=True)
            lines.append(f"      {lua_field_key(p['name'])} = T.nullable({validator}),")
        lines.append("    }),")

    if op["body_schema"] and op["body_schema"].get("type") == "object":
        lines.append(f"    content_types = {{ 'application/json' }},")
        body_lua = object_schema_lua(op["body_schema"], indent="    ")
        lines.append(f"    json = {body_lua},")

    lines.append("  },")
    return "\n".join(lines)


def main():
    with open(IN_PATH, encoding="utf-8") as f:
        data = json.load(f)

    unrecognized = set()
    route_blocks = [route_lua(op, unrecognized) for op in data["operations"]]

    out = []
    out.append("-- rootfs/etc/openresty/waf/apps/gitea/api_schema.lua")
    out.append("-- Generated by gen_api_schema.py from gitea-api-extracted.json (itself")
    out.append("-- produced by extract_swagger.py from Gitea's checked-in swagger spec) -")
    out.append("-- do not hand-edit, re-run the generator.")
    out.append("local T = require \"waf.types\"")
    out.append("")
    out.append("return {")
    out.append("  routes = {")
    out.extend(route_blocks)
    out.append("  },")
    out.append("}")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

    print(f"Wrote {OUT_PATH}: {len(route_blocks)} routes")
    if unrecognized:
        print(f"WARNING: {len(unrecognized)} path param name(s) fell through to the "
              f"generic fallback pattern (review these): {sorted(unrecognized)}")


if __name__ == "__main__":
    main()

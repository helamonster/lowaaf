#!/usr/bin/env python3
"""
Generates rootfs/etc/openresty/waf/apps/gitea/web_routes.lua from
gitea-web-extracted.json (extract_web_routes.py's output) - one route per
extracted (method, path) entry, with a `form` schema attached wherever the
route's web.Bind(forms.XForm{}) reference resolves to a real struct in
services/forms/*.go.

Web forms carry no json:/form: struct tags at all (confirmed directly -
grepped every file in services/forms/) - the wire field name is the bare Go
struct field name as-is (Gitea's own convention: form fields are
PascalCase, matching the Go identifier, unlike the snake_case JSON API).
Embedded fields (e.g. `NewWebhookForm` embeds `WebhookForm` anonymously)
are flattened via Go's normal promotion rules - handled as a second
resolution pass over the parsed struct index.

No CSRF token field to account for: Gitea uses Go's standard-library
net/http.CrossOriginProtection (Sec-Fetch-Site/Origin header based, see
routers/web/web.go's crossOriginProtection.Check(...)), not a hidden
form-field token - those headers are already in T.common_request_headers().

Usage: python3 gen_web_routes.py
"""
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root, lua_str, field_key  # noqa: E402

REPO_ROOT = find_repo_root(SCRIPT_DIR)
GITEA_ROOT = os.path.join(REPO_ROOT, "app-sources", "gitea", "gitea")
FORMS_DIR = os.path.join(GITEA_ROOT, "services", "forms")
IN_PATH = os.path.join(SCRIPT_DIR, "gitea-web-extracted.json")
OUT_PATH = os.path.join(
    REPO_ROOT, "rootfs", "etc", "openresty", "waf", "apps", "gitea", "web_routes.lua"
)

SHORT_STRING_MAX = 1024
LONG_STRING_MAX = 65536
LONG_TEXT_FIELD_HINTS = (
    "body", "content", "description", "message", "comment", "text", "readme",
    "note", "payload", "message", "changelog",
)

# --- path-parameter -> regex fragment (bare {name}, no inline constraint) --
NUMERIC_PATH_PARAMS = {
    "id", "index", "runnerid", "variable_id", "columnID", "userid", "qid",
    "idx", "authid", "timeid", "job", "grantId", "pid", "lid", "size",
}
HEX_PATH_PARAMS = {"uuid", "sha", "oid", "hash", "shaFrom", "shaTo"}
NAME_PATH_PARAMS = {
    "username", "reponame", "org", "team", "provider", "name", "action",
    "type", "run", "badge_slug", "token", "artifact_name", "period", "vTag",
    "fileName", "workflow_name",
}


def bare_param_fragment(name, unrecognized):
    if name in NUMERIC_PATH_PARAMS:
        return r"[0-9]+"
    if name in HEX_PATH_PARAMS:
        return r"[0-9a-fA-F-]{1,64}"
    if name in NAME_PATH_PARAMS:
        return r"[\da-zA-Z][-.\w]{0,99}"
    unrecognized.add(name)
    return r"[^/]{1,255}"


def is_single_group(pattern):
    """True if `pattern` is already one self-contained, balanced
    parenthesized group covering the whole string (e.g. Gitea's own
    "([a-f0-9]{7,64})") - wrapping it in another (?:...) would double-nest,
    which test/gen.lua's path-regex-to-test-URI reverser (built for one
    level of grouping) can't unwrap cleanly."""
    if not (pattern.startswith("(") and pattern.endswith(")")):
        return False
    depth = 0
    for idx, c in enumerate(pattern):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return idx == len(pattern) - 1
    return False


def parse_path_params(path, unrecognized):
    """Converts a chi route path (with {name} / {name:regex} / '*'
    wildcard tokens) into a PCRE fragment string. {name:regex} constraints
    are used as-is (brace-depth-aware, since the constraint itself can
    contain nested braces - e.g. {sha:([a-f0-9]{7,64})}) rather than
    guessed from the name - more precise than Phase 1 ever could be, since
    chi's own constraint IS the real validation Gitea applies."""
    out = []
    i = 0
    n = len(path)
    while i < n:
        c = path[i]
        if c == "{":
            depth = 1
            j = i + 1
            while depth > 0:
                if path[j] == "{":
                    depth += 1
                elif path[j] == "}":
                    depth -= 1
                j += 1
            token = path[i + 1:j - 1]
            if ":" in token:
                name, pattern = token.split(":", 1)
                # A handful of Gitea's own chi constraints end in a literal
                # "$" (e.g. "{sha:([a-f0-9]{7,64})$}", confirmed directly
                # in web.go) - meaningful to chi's own per-segment matching,
                # but wrong once wrapped in a path we anchor ourselves with
                # a single trailing $: an embedded mid-pattern "$" forbids
                # any trailing path segment from ever matching (confirmed
                # live - denied a request with a real path after the sha).
                if pattern.endswith("$"):
                    pattern = pattern[:-1]
                out.append(pattern if is_single_group(pattern) else "(?:" + pattern + ")")
            else:
                out.append(bare_param_fragment(token, unrecognized))
            i = j
        elif c == "*":
            out.append(r"[^\x00-\x1f]*")
            i += 1
        elif c == ".":
            out.append(r"\.")
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


# --- services/forms/*.go struct + binding-tag parsing ----------------------

FIELD_RE = re.compile(
    r'^\s*(?P<name>[A-Z]\w*)\s+(?:\*)?(?P<type>[\[\]A-Za-z0-9_.]+)\s*'
    r'(?:`(?P<tag>[^`]*)`)?\s*(?://.*)?$'
)
TAG_ITEM_RE = re.compile(r'(\w+):"([^"]*)"')
TYPE_STRUCT_RE = re.compile(r'^type\s+(\w+)\s+struct\s*\{\s*$')


def parse_go_structs(text):
    """Returns {struct_name: {"fields": {go_name: {"type", "binding"}},
    "embeds": [type_name, ...]}}."""
    structs = {}
    lines = text.splitlines()
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
        embeds = []
        for line in body:
            stripped = line.strip()
            fm = FIELD_RE.match(line)
            if fm:
                tag_items = dict(TAG_ITEM_RE.findall(fm.group("tag") or ""))
                fields[fm.group("name")] = {
                    "type": fm.group("type"),
                    "binding": tag_items.get("binding", ""),
                }
            elif re.match(r"^[A-Z]\w*$", stripped):
                # Bare type name, no field name of its own - an anonymous
                # embedded field (Go struct promotion).
                embeds.append(stripped)
        structs[name] = {"fields": fields, "embeds": embeds}
    return structs


def build_forms_index():
    structs = {}
    for fname in sorted(os.listdir(FORMS_DIR)):
        if not fname.endswith(".go") or fname.endswith("_test.go"):
            continue
        text = open(os.path.join(FORMS_DIR, fname), encoding="utf-8").read()
        structs.update(parse_go_structs(text))

    def resolve(name, seen=None):
        seen = seen or set()
        if name in seen or name not in structs:
            return {}
        seen = seen | {name}
        fields = dict(structs[name]["fields"])
        for embed in structs[name]["embeds"]:
            fields.update(resolve(embed, seen))
        return fields

    return {name: resolve(name) for name in structs}


# --- binding-tag -> T.* -------------------------------------------------------

def parse_binding(binding_str):
    rules = []
    for part in binding_str.split(";"):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(\w+)(?:\(([^)]*)\))?$", part)
        if m:
            rules.append((m.group(1), m.group(2)))
    return rules


def field_validator(go_type, binding_str, field_name):
    rules = dict(parse_binding(binding_str))
    is_required = "Required" in rules

    # Form values always arrive as strings over the wire (urlencoded or
    # multipart - neither has a native bool/int type), same reason Phase 1
    # uses T.number_query()/T.bool_query() for GET query params instead of
    # T.number()/T.boolean() (which expect real parsed JSON types).
    # Confirmed live: T.boolean()/T.number() denied every real form
    # submission with a numeric or boolean field - the value never matches
    # the Lua type they require.
    if go_type == "bool":
        v = "T.bool_query()"
    elif go_type in ("int", "int64", "int32", "uint", "uint64", "float64"):
        opts = ["integer=true"] if "float" not in go_type else []
        range_rule = rules.get("Range")
        if range_rule:
            lo, hi = [x.strip() for x in range_rule.split(",")]
            opts.append(f"min={lo}")
            opts.append(f"max={hi}")
        else:
            opts.append("max=2147483647")
        v = "T.number_query({ " + ", ".join(opts) + " })"
    else:
        opts = []
        max_size = rules.get("MaxSize")
        in_rule = rules.get("In")
        if "Email" in rules:
            v = "T.email()"
            return v if is_required else f"T.nullable({v})"
        if in_rule is not None:
            values = [x.strip() for x in in_rule.split(",") if x.strip()]
            enum_lua = ", ".join(f"{field_key(x)}=true" for x in values)
            opts.append(f"enum={{ {enum_lua} }}")
        if max_size is not None:
            opts.append(f"max={max_size}")
        elif in_rule is None:
            default_max = LONG_STRING_MAX if any(
                hint in field_name.lower() for hint in LONG_TEXT_FIELD_HINTS
            ) else SHORT_STRING_MAX
            opts.append(f"max={default_max}")
        v = "T.string({ " + ", ".join(opts) + " })"

    return v if is_required else f"T.nullable({v})"


def form_schema_lua(fields, indent="    "):
    lines = ["T.object({"]
    for name in sorted(fields.keys()):
        info = fields[name]
        validator = field_validator(info["type"], info["binding"], name)
        lines.append(f"{indent}  {field_key(name)} = {validator},")
    lines.append(indent + "})")
    return "\n".join(lines)


# --- route emission -----------------------------------------------------------

ALL_METHODS_LUA = "{ 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS' }"


def route_lua(entry, forms_index, unrecognized, name_counts):
    methods = entry["methods"]
    method = methods[0].upper()
    path_frag = parse_path_params(entry["path"], unrecognized)
    base_name = f"gitea web {method} {entry['path']}"
    name_counts[base_name] = name_counts.get(base_name, 0) + 1
    name = base_name if name_counts[base_name] == 1 else f"{base_name} #{name_counts[base_name]}"

    lines = ["  {"]
    lines.append(f"    name = {lua_str(name)},")
    if method == "ANY":
        # m.Any(path, handler) - chi's own "match every method" - there's
        # no per-route equivalent in this framework, so expand to every
        # method the app allows globally (matches gitea.lua's own
        # allowed_methods) rather than guessing at a single "real" one.
        lines.append(f"    methods = {ALL_METHODS_LUA},")
    else:
        lines.append(f"    method = {lua_str(method)},")
    lines.append(f"    path = {lua_str('^' + path_frag + '$')},")

    form_name = entry.get("form")
    if form_name and form_name in forms_index and forms_index[form_name]:
        body_lua = form_schema_lua(forms_index[form_name])
        lines.append(f"    form = {body_lua},")

    lines.append("  },")
    return "\n".join(lines)


def main():
    with open(IN_PATH, encoding="utf-8") as f:
        data = json.load(f)
    forms_index = build_forms_index()

    unrecognized = set()
    name_counts = {}
    route_blocks = [route_lua(r, forms_index, unrecognized, name_counts) for r in data["routes"]]

    out = []
    out.append("-- rootfs/etc/openresty/waf/apps/gitea/web_routes.lua")
    out.append("-- Generated by gen_web_routes.py from gitea-web-extracted.json (itself")
    out.append("-- produced by extract_web_routes.py from routers/web/web.go) - do not")
    out.append("-- hand-edit, re-run the generator.")
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
    forms_used = {r["form"] for r in data["routes"] if r.get("form")}
    forms_resolved = {f for f in forms_used if f in forms_index and forms_index[f]}
    print(f"forms referenced: {len(forms_used)}, resolved with >=1 field: {len(forms_resolved)}")
    if forms_used - forms_resolved:
        print(f"WARNING: unresolved forms: {sorted(forms_used - forms_resolved)}")
    if unrecognized:
        print(f"WARNING: {len(unrecognized)} bare path param name(s) fell through to the "
              f"generic fallback pattern (review these): {sorted(unrecognized)}")


if __name__ == "__main__":
    main()

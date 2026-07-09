#!/usr/bin/env python3
"""
Converts mw-api-extract/api-params.json into Lua {field = T.xxx(...)} table
bodies, one per module, for hand-review before pasting into mediawiki.lua.

Usage: python3 gen_lua_fields.py api-params.json [module_key ...]
  (no module_key args = emit all modules)
"""
import sys, json, re

STRING_DEFAULT_MAX = 512
TEXT_MAX = 1024 * 1024
MULTI_MAX = 2048  # pipe-joined multi-value strings

def lua_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

def enum_table(values):
    return "{ " + ", ".join(f"[{lua_str(v)}]=true" for v in values) + " }"

def field_lua(name, spec):
    t = spec.get("type", "string")
    ismulti = spec.get("ismulti", False)
    required = spec.get("required", False)
    comment = ""  # appended AFTER the full expression + trailing comma - never inside it

    if "dynamic_type_expr" in spec:
        # Lua line comments end at the first newline - the PHP source snippet
        # can span multiple lines, so it must be collapsed to one line or it
        # would silently turn the rest of the original line into live code.
        flat_expr = re.sub(r"\s+", " ", spec["dynamic_type_expr"]).strip()
        comment = f"  -- dynamic enum from {flat_expr!r}, left generic"

    if t == "enum":
        vals = spec.get("enum", [])
        max_len = max([len(v) for v in vals] + [1])
        if ismulti:
            inner = f"T.string({{ max={MULTI_MAX} }})"
            flat_vals = ", ".join(re.sub(r"\s+", " ", v).strip() for v in vals)
            comment = comment or f"  -- pipe-separated list of: {flat_vals}"
        else:
            inner = f"T.string({{ max={max_len}, enum={enum_table(vals)} }})"
    elif t == "boolean":
        # MediaWiki API "boolean" params are presence-based (any value, even
        # empty string, means true; the key's absence means false) - NOT
        # JSON true/false. These are always query-string/form values here
        # (api.php has no JSON body), which arrive as plain strings, so
        # T.boolean() (which requires a real Lua boolean, e.g. from a JSON
        # body) is the wrong validator; use a short capped string instead.
        inner = "T.string({ max=8 })"
    elif t in ("integer", "limit"):
        opts = ["integer=true"]
        if "param_min" in spec: opts.append(f"min={spec['param_min']}")
        if "param_max" in spec: opts.append(f"max={spec['param_max']}")
        inner = f"T.number_query({{ {', '.join(opts)} }})"
    elif t == "text":
        inner = f"T.string({{ max={TEXT_MAX} }})"
    elif t == "password":
        inner = f"T.string({{ max=256 }})"
        comment = comment or "  -- sensitive"
    elif t in ("user", "timestamp", "namespace", "tags", "upload", "raw"):
        cap = MULTI_MAX if ismulti else STRING_DEFAULT_MAX
        inner = f"T.string({{ max={cap} }})"
        comment = comment or f"  -- mediawiki type: {t}"
    else:  # "string" and anything unrecognized
        cap = MULTI_MAX if ismulti else STRING_DEFAULT_MAX
        inner = f"T.string({{ max={cap} }})"

    if not required:
        inner = f"T.nullable({inner})"

    return f"  {name} = {inner},{comment}"

def main():
    path = sys.argv[1]
    keys = sys.argv[2:]
    data = json.load(open(path))
    targets = keys if keys else sorted(data.keys())
    for key in targets:
        if key not in data:
            print(f"-- WARNING: module '{key}' not found", file=sys.stderr)
            continue
        mod = data[key]
        print(f"-- {key} ({mod['class']}, {mod['kind']}) -- {mod['file']}")
        print(f"{key} = {{")
        for pname, spec in sorted(mod["params"].items()):
            print(field_lua(pname, spec))
        print("},")
        print()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
One-shot generator: reads api-params.json and emits ALL remaining tiers'
Lua as ready-to-paste chunks in one file, instead of generating module-by-
module across many separate commands.

Usage: python3 gen_all_tiers.py api-params.json > mw_tiers_out.lua
"""
import sys, json, re

STRING_DEFAULT_MAX = 512
TEXT_MAX = 1024 * 1024
MULTI_MAX = 2048

TIER2 = ["edit","delete","undelete","protect","block","unblock","move","upload",
         "filerevert","emailuser","watch","patrol","import","userrights","options",
         "imagerotate","revisiondelete","managetags","tag","mergehistory",
         "setpagelanguage","changecontentmodel","rollback","stashedit"]
TIER5 = ["opensearch","expandtemplates","parse","feedcontributions","feedrecentchanges",
         "feedwatchlist","help","paraminfo","rsd","compare","cspreport","purge",
         "setnotificationtimestamp","languagesearch"]

def lua_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

def enum_table(values):
    return "{ " + ", ".join(f"[{lua_str(v)}]=true" for v in values) + " }"

def field_lua(name, spec, indent="    "):
    t = spec.get("type", "string")
    ismulti = spec.get("ismulti", False)
    required = spec.get("required", False)
    comment = ""

    if "dynamic_type_expr" in spec:
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
        # Presence-based in MediaWiki's API (any value = true, absent = false),
        # arrives as a plain query/form string here, never a JSON boolean.
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
    else:
        cap = MULTI_MAX if ismulti else STRING_DEFAULT_MAX
        inner = f"T.string({{ max={cap} }})"

    if not required:
        inner = f"T.nullable({inner})"

    key = name if re.match(r"^[A-Za-z_]\w*$", name) and name not in ("end", "continue", "type", "repeat", "function") else f"[{lua_str(name)}]"
    return f"{indent}{key} = {inner},{comment}"

def emit_module_block(key, mod, indent="  "):
    lines = [f"{indent}{key} = {{"]
    for pname, spec in sorted(mod["params"].items()):
        lines.append(field_lua(pname, spec, indent + "  "))
    lines.append(f"{indent}}},")
    return "\n".join(lines)

def main():
    data = json.load(open(sys.argv[1]))

    print("-- ==========================================================================")
    print("-- TIER 2: write/mutation action modules")
    print("-- Paste each block's contents into mw_api_actions in mediawiki.lua")
    print("-- ==========================================================================")
    for key in TIER2:
        if key not in data:
            print(f"-- MISSING from extraction: {key}")
            continue
        mod = data[key]
        print(f"-- {key} ({mod['class']}) -- {mod['file']}")
        print(emit_module_block(key, mod))
        print()

    print("-- ==========================================================================")
    print("-- TIER 5: remaining read/utility action modules")
    print("-- ==========================================================================")
    for key in TIER5:
        if key not in data:
            print(f"-- MISSING from extraction: {key}")
            continue
        mod = data[key]
        print(f"-- {key} ({mod['class']}) -- {mod['file']}")
        print(emit_module_block(key, mod))
        print()

    print("-- ==========================================================================")
    print("-- TIER 3 + 4: action=query submodules (prop=/list=/meta=)")
    print("-- These are looked up by NAME from prop=/list=/meta= (pipe-separated), not")
    print("-- from `action` directly - paste into mw_query_submodules, keyed by kind.")
    print("-- ==========================================================================")
    for kind in ("meta", "prop", "list"):
        mods = {k: v for k, v in data.items() if v["kind"] == kind}
        print(f"-- ---- {kind} submodules ({len(mods)}) ----")
        for key in sorted(mods):
            mod = mods[key]
            print(f"-- {key} ({mod['class']}) -- {mod['file']}")
            print(emit_module_block(key, mod))
            print()

if __name__ == "__main__":
    main()

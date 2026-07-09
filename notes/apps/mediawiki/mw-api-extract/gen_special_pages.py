#!/usr/bin/env python3
"""
Generates Lua route + form-schema blocks for write-capable Special: pages,
from the heuristic candidate_fields in mw-api-extract/special-fields.json.

These are candidate field NAMES only (no type/requiredness info - the scan
is a grep over $request->getVal()/getText()/... calls and HTMLForm literal
keys, not a structured extraction like the API modules), so every field is
modeled as a generously-capped nullable string. Precision here is "reject
completely unknown fields", not "validate each field's exact shape" - the
same conservative treatment used for the EditPage index.php POST form.

Usage: python3 gen_special_pages.py > special_pages_out.lua
"""
import json
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# label -> (Special: page name, extra fields not caught by the heuristic scan
# but known to be part of the real form from reading the source directly)
PAGES = {
    "upload": "Special:Upload",
    "block": "Special:Block",
    "unblock": "Special:Unblock",
    "movepage": "Special:Movepage",
    "userrights": "Special:Userrights",
    "import": "Special:Import",
    "export": "Special:Export",
    "undelete": "Special:Undelete",
    "emailuser": "Special:Emailuser",
    "mergehistory": "Special:MergeHistory",
    "blocklist": "Special:BlockList",
    "changecontentmodel": "Special:ChangeContentModel",
}

# Long-content fields get a bigger cap than the generic default.
LONG_FIELDS = {
    "wpUploadDescription": 1024 * 64,
    "wpReason": 1024,
    "wpRemovalReason": 1024,
    "wpComment": 1024,
    "wpCommentList": 2048,
}

DEFAULT_MAX = 512


def lua_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def field_key(name):
    return name if re.match(r"^[A-Za-z_]\w*$", name) else f"[{lua_str(name)}]"


def emit_fields(fields, indent):
    lines = []
    for name in sorted(set(fields)):
        cap = LONG_FIELDS.get(name, DEFAULT_MAX)
        lines.append(f"{indent}{field_key(name)} = T.nullable(T.string({{ max={cap} }})),")
    return "\n".join(lines)


def main():
    with open(os.path.join(SCRIPT_DIR, "special-fields.json")) as f:
        data = json.load(f)

    print("-- Write-capable Special: pages (Tier 6), heuristically extracted.")
    print("-- Candidate field NAMES only (no type info) - every field is a generously")
    print("-- capped nullable string; precision here is 'unknown fields are rejected',")
    print("-- not 'each field's exact shape is validated' (same treatment as the")
    print("-- EditPage index.php POST form above).")
    print()
    for label, page_name in PAGES.items():
        cls_key = page_name.split(":", 1)[1]  # "Special:Upload" -> "Upload"
        entry = data.get(cls_key)
        if not entry or not entry.get("candidate_fields"):
            print(f"-- {label} ({page_name}): NO CANDIDATE FIELDS FOUND - skipped, needs manual review")
            print()
            continue
        print(f"-- {label} ({page_name}, {entry['class']}) -- {entry['file']}")
        print(f"local {label}_form = T.object({{")
        print(emit_fields(entry["candidate_fields"], "  "))
        print("})")
        print()
        print(f"local {label}_route = {{")
        print(f"  name    = \"index php special {label} post\",")
        print(f"  method  = \"POST\",")
        print(f"  path    = [[^/index\\.php/{page_name}(?:/.*)?$]],")
        print(f"  content_types = {{ \"application/x-www-form-urlencoded\", \"multipart/form-data\" }},")
        print(f"  form    = {label}_form,")
        print("}")
        print()


if __name__ == "__main__":
    main()

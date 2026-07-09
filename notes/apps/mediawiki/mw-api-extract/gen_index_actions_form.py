#!/usr/bin/env python3
"""
Generates one Lua form schema per index.php action=X POST form (delete,
protect, purge, revert, rollback, watch/unwatch, markpatrolled, mcrundo,
mcrrestore, ...) from index-actions.json, plus a `mw_index_action_forms`
array listing them all.

These are additional to index_post_form (the edit/submit form) - the
"index php post" route accepts ALL of them via form_schemas (core.lua tries
each schema in turn, passes if any matches), since which action= a given
POST is for lives in the query string, not the body.

Usage: python3 gen_index_actions_form.py > index_actions_form_out.lua
"""
import json
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_MAX = 512
LONG_FIELD_HINTS = {
    "reason": 1024,
    "comment": 1024,
    "summary": 2048,
}

BOOLEAN_FIELDS = {"wpDeleteTalk", "wpSuppress", "wpWatch"}


def lua_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


LUA_RESERVED = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while",
}


def field_key(name):
    if re.match(r"^[A-Za-z_]\w*$", name) and name not in LUA_RESERVED:
        return name
    return f"[{lua_str(name)}]"


def cap_for(name):
    lname = name.lower()
    for hint, cap in LONG_FIELD_HINTS.items():
        if hint in lname:
            return cap
    return DEFAULT_MAX


def field_lua(name, indent):
    if name in BOOLEAN_FIELDS:
        inner = "T.nullable(T.string({ max=8 }))"
    else:
        inner = f"T.nullable(T.string({{ max={cap_for(name)} }}))"
    return f"{indent}{field_key(name)} = {inner},"


def label_for(cls):
    return re.sub(r"[^a-z0-9]", "", cls.lower())


def main():
    with open(os.path.join(SCRIPT_DIR, "index-actions.json")) as f:
        data = json.load(f)

    print("-- ---------------------------------------------------------------------------")
    print("-- index.php action=X POST forms (includes/Actions/*.php + Page/ProtectionForm.php).")
    print("-- Generated from index-actions.json (extract_mediawiki_api.py). Candidate field")
    print("-- NAMES only (getFormFields() types where available, else a heuristic scan), so")
    print("-- fields are generously-capped nullable strings - same convention as the Special:")
    print("-- page routes. title/wpEditToken/wpFormIdentifier are added to every form: they're")
    print("-- injected unconditionally by HTMLForm::getHiddenFields() for any POST-method form,")
    print("-- not read back by the action's own code, so no scan of it ever finds them.")
    print("-- Which action= a POST is for lives in the query string (index_query already")
    print("-- allows it), not the body, so all of these are added to 'index php post' via")
    print("-- form_schemas - core.lua tries each in turn and passes if any one matches.")
    print("-- ---------------------------------------------------------------------------")

    labels = []
    for cls in sorted(data.keys()):
        entry = data[cls]
        label = label_for(cls)
        labels.append(label)
        fields = dict(entry.get("fields") or {})
        fields.setdefault("title", {"type": "string"})
        fields.setdefault("wpEditToken", {"type": "string"})
        fields.setdefault("wpFormIdentifier", {"type": "string"})

        print(f"-- {cls} (action={entry.get('action')!r}, method={entry.get('method')}) -- {entry.get('file')}")
        print(f"local action_{label}_form = T.object({{")
        for name in sorted(fields):
            print(field_lua(name, "  "))
        print("})")
        print()

    print("local mw_index_action_forms = {")
    for label in labels:
        print(f"  action_{label}_form,")
    print("}")


if __name__ == "__main__":
    main()

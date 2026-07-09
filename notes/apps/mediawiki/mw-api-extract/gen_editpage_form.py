#!/usr/bin/env python3
"""
Generates the `local index_post_form = T.object({...})` schema (the standard
wikitext edit-submission form, EditPage.php) from editpage-fields.json.

Field names are candidate names only (heuristic $request->getXxx() scan, no
type info), so most are modeled as generously-capped nullable strings - same
convention as gen_all_special_pages.py. A handful of known enum/boolean
fields get a tighter FIELD_OVERRIDES entry since their real shape is obvious
from MediaWiki's UI conventions (presence-based checkboxes, the fixed
wpUltimateParam anti-spoofing sentinel).

Usage: python3 gen_editpage_form.py > editpage_form_out.lua
"""
import json
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_MAX = 512
LONG_FIELD_HINTS = {
    "textbox": 1024 * 1024,   # wpTextbox1/wpTextbox2 - full page content
    "summary": 2048,
    "changetags": 2048,
    "preloadparams": 2048,
    "watchlistlabels": 2048,  # MenuTagMultiselectWidget - can hold several selections
}

# Presence-based checkboxes (any submitted value means "checked") - same
# convention as the MediaWiki API's boolean params elsewhere in this file.
# wpSave is NOT one of these despite looking like a submit flag: classic
# <input type=submit name=wpSave value="Save changes"> buttons submit their
# translated DISPLAY LABEL as the value ("Save changes" = 13 chars, other
# languages/skins can run longer), not a short fixed token - capping it at
# 8 like a real boolean flag false-positived on every real save (confirmed
# live: max=8 rejected the literal string "Save changes").
BOOLEAN_FIELDS = {
    "bot", "minor", "nosummary", "preview", "redlink", "watchthis",
    "wpMinoredit", "wpPreview", "wpWatchthis", "wpIgnoreBlankArticle",
    "wpIgnoreBlankSummary", "wpIgnoreProblematicRedirects",
    "wpIgnoreRevisionDeleted", "wpRecreate", "wpAllowedProblematicRedirectTarget",
    "wpChangeTagsAfterPreview",
}

# Fields with a known fixed/enum shape that the generic string treatment
# would blur.
FIELD_OVERRIDES = {
    "wpUltimateParam": "T.nullable(T.string({ max=4, enum={ ['1']=true } }))",
    "wpUnicodeCheck": "T.nullable(T.string({ max=64 }))",  # fixed UTF-8 sanity-check string
    "wpAntispam": "T.nullable(T.string({ max=64 }))",  # honeypot; MediaWiki rejects non-empty values
}


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
    if name in FIELD_OVERRIDES:
        inner = FIELD_OVERRIDES[name]
    elif name in BOOLEAN_FIELDS:
        inner = "T.nullable(T.string({ max=8 }))"
    else:
        inner = f"T.nullable(T.string({{ max={cap_for(name)} }}))"
    return f"{indent}{field_key(name)} = {inner},"


def main():
    with open(os.path.join(SCRIPT_DIR, "editpage-fields.json")) as f:
        entry = json.load(f)
    fields = sorted(entry.get("fields") or {})

    print("-- ---------------------------------------------------------------------------")
    print("-- index.php POST form schema - the standard wikitext edit-submission form")
    print("-- (EditPage.php). Generated from editpage-fields.json (extract_mediawiki_api.py,")
    print("-- heuristic $request->getXxx() scan - candidate field NAMES only, no type info,")
    print("-- so most fields are generously-capped nullable strings; a handful of known")
    print("-- checkbox/enum fields get a tighter FIELD_OVERRIDES entry in gen_editpage_form.py.")
    print("-- None are marked required since MediaWiki's own form-building logic determines")
    print("-- which fields are present per action (preview/save/diff).")
    print("-- ---------------------------------------------------------------------------")
    print("local index_post_form = T.object({")
    for name in fields:
        print(field_lua(name, "  "))
    print("})")


if __name__ == "__main__":
    main()

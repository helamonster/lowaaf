#!/usr/bin/env python3
"""
Generates dedicated Lua routes for ALL 132 core Special: pages from
special-fields.json, reconciled with the 16 pages already precisely
hand-tuned as GET routes in mw_special_pages (AllPages, ListUsers,
RecentChangesLinked, Redirect, ProtectedTitles, Log, ActiveUsers,
ComparePages, WhatLinksHere, LinkSearch, MIMESearch, NewPages, MergeHistory,
PagesWithProp, Contributions, AllMessages) - these keep their existing GET
route untouched; this script only adds a POST route for them if real
submitted fields were found (e.g. MergeHistory).

Every page gets a dedicated GET route (query = idx_common, plus any
redirect-passthrough fields; no_body = true) unless it already has one from
the hand-tuned set above. Pages with real submitted fields (form_fields or
heuristic method) additionally get a POST route with those fields as a form
schema. Pages with nothing found (query_page_standard / none / empty
redirect_passthrough) get ONLY the bare GET route - no page-specific extra
parameters allowed, per instruction.

Output is a SINGLE Lua array literal (`local mw_bulk_special_routes = {...}`)
with every route as an anonymous inline table - not one named `local` per
route/form. Lua caps a chunk at 200 locals; with ~160 generated routes plus
per-route form schemas, individually-named locals blow straight through that
ceiling. A single local holding an array has no such limit on its contents.

Usage: python3 gen_all_special_pages.py > all_special_pages_out.lua
"""
import json
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Already have a precisely hand-tuned GET route via mw_special_pages / the
# dedicated allmessages_route - don't generate a duplicate GET route for these.
# MediaWiki case-folds special page names before resolving them (see
# SpecialPageFactory::resolveAlias()), so CORE_LIST's internal key casing
# (e.g. "Allpages", "Whatlinkshere") doesn't necessarily match what's in a
# real URL - compare case-insensitively rather than trying to guess which
# casing is "the real one".
ALREADY_HAS_GET_ROUTE = {s.lower() for s in {
    "AllPages", "ListUsers", "RecentChangesLinked", "Redirect", "ProtectedTitles",
    "Log", "ActiveUsers", "ComparePages", "WhatLinksHere", "LinkSearch",
    "MIMESearch", "NewPages", "MergeHistory", "PagesWithProp", "Contributions",
    "AllMessages",
}}

DEFAULT_MAX = 512
LONG_FIELD_HINTS = {
    "reason": 1024, "comment": 1024, "summary": 2048, "description": 1024 * 64,
    "text": 1024 * 1024, "commentlist": 2048,
}

# core.lua's multipart parser records just the filename (not the raw file
# bytes) for any part with a filename= attribute, so wpUploadFile's *value*
# is always short - but the overall request body (which DOES include the
# real file bytes, counted via Content-Length before parsing) needs a much
# bigger max_body than the 4MB app default. $wgMaxUploadSize's own MediaWiki
# default is 100MB (includes/config-schema.php); +1MB slack for the other
# form fields/multipart boundary overhead. Adjust if a deployment's real
# $wgMaxUploadSize/php.ini upload_max_filesize differs.
MAX_BODY_OVERRIDES = {
    "Upload": 100 * 1024 * 1024 + 1024 * 1024,
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


def label_for(page_key):
    # "BlockList" -> "blocklist", "MIMESearch" -> "mimesearch"
    return re.sub(r"[^a-z0-9]", "", page_key.lower())


def cap_for(name, spec):
    lname = name.lower()
    for hint, cap in LONG_FIELD_HINTS.items():
        if hint in lname:
            return cap
    return DEFAULT_MAX


def field_lua(name, spec, indent):
    t = spec.get("type", "string")
    required = spec.get("required", False)

    if t == "enum" and spec.get("enum"):
        vals = spec["enum"]
        max_len = max([len(v) for v in vals] + [1])
        inner = f"T.string({{ max={max_len}, enum={{ " + ", ".join(f"[{lua_str(v)}]=true" for v in vals) + " } })"
    elif t == "boolean":
        inner = "T.string({ max=8 })"  # presence-based, same convention as API booleans
    elif t == "integer":
        inner = "T.number_query({ integer=true })"
    else:
        inner = f"T.string({{ max={cap_for(name, spec)} }})"

    if not required:
        inner = f"T.nullable({inner})"
    return f"{indent}{field_key(name)} = {inner},"


def emit_fields(fields, indent):
    return "\n".join(field_lua(n, s, indent) for n, s in sorted(fields.items()))


def main():
    with open(os.path.join(SCRIPT_DIR, "special-fields.json")) as f:
        data = json.load(f)

    print("-- ==========================================================================")
    print("-- Dedicated routes for every core Special: page (Tier 6, full coverage).")
    print("-- Generated from special-fields.json (extract_mediawiki_api.py). Field data")
    print("-- comes from, in priority order: FormSpecialPage::getFormFields() (precise")
    print("-- types), a redirect stub's constructor pass-through list, or a heuristic")
    print("-- $request->getXxx() scan (generic strings). QueryPage-family report pages")
    print("-- and pages where nothing was found get no page-specific extra fields at")
    print("-- all - just the common index.php baseline (idx_common). One array local,")
    print("-- not one named local per route/form (Lua caps a chunk at 200 locals).")
    print("-- ==========================================================================")
    print("local mw_bulk_special_routes = {")

    # Every page's POST form gets ALSO collected here (see below the route
    # array) - the dedicated "index php special X post" routes above only
    # match /index.php/Special:X PATH-style URLs. Route matching is purely
    # URI-path-based and happens before the query string is even parsed, so
    # a request using /index.php?title=Special:X (query-string style - what
    # a self-submitting HTMLForm actually generates, e.g.
    # Special:EditWatchlist/raw's save button) can NEVER reach these
    # dedicated routes no matter what title= says - it always falls through
    # to the generic "index php post" catch-all instead, which never knew
    # about ANY of these 132 pages' fields. Confirmed live: EditWatchlist's
    # wpTitles got rejected on exactly this path. Fix is in
    # integrate_all_special_pages.py, which splices this into the generic
    # route's form_schemas.
    special_post_forms = []

    for page_key in sorted(data.keys()):
        entry = data[page_key]
        label = label_for(page_key)
        fields = entry.get("fields") or {}
        method = entry["method"]
        page_name = f"Special:{page_key}"

        has_get_already = page_key.lower() in ALREADY_HAS_GET_ROUTE
        # redirect_passthrough fields are GET-navigable query params (e.g.
        # returnto/returntoquery); form_fields/heuristic fields are POST-submitted.
        get_extra_fields = fields if method == "redirect_passthrough" else {}
        post_fields = fields if method in ("form_fields", "heuristic") else {}
        if post_fields:
            # HTMLForm::getHiddenFields() unconditionally injects title (for
            # any POST-method form) and wpEditToken, and conditionally
            # wpFormIdentifier, into EVERY HTMLForm-built form - added by the
            # framework itself, not by the page's own source, so neither
            # getFormFields() nor the heuristic $request-> scan ever sees
            # them. Without this every generated POST form false-positives on
            # the very first submit (observed live for Special:Upload).
            post_fields = dict(post_fields)
            post_fields.setdefault("title", {"type": "string"})
            post_fields.setdefault("wpEditToken", {"type": "string"})
            post_fields.setdefault("wpFormIdentifier", {"type": "string"})

        print(f"  -- {page_key} ({entry.get('class')}, extends={entry.get('extends')}, method={method})"
              + (f" -- {entry['file']}" if entry.get("file") else ""))

        if not has_get_already:
            print("  {")
            print(f"    name    = \"index php special {label}\",")
            print(f"    method  = \"GET\",")
            print(f"    path    = [[(?i)^/index\\.php/{page_name}(?:/.*)?$]],")
            if get_extra_fields:
                print(f"    query   = T.object(merge(idx_common, {{")
                print(emit_fields(get_extra_fields, "      "))
                print("    })),")
            else:
                print(f"    query   = T.object(idx_common),")
            print("    no_body = true,")
            print("  },")

        if post_fields:
            print("  {")
            print(f"    name    = \"index php special {label} post\",")
            print(f"    method  = \"POST\",")
            print(f"    path    = [[(?i)^/index\\.php/{page_name}(?:/.*)?$]],")
            print("    content_types = { \"application/x-www-form-urlencoded\", \"multipart/form-data\" },")
            if page_key in MAX_BODY_OVERRIDES:
                print(f"    max_body = {MAX_BODY_OVERRIDES[page_key]},")
            print(f"    form    = T.object({{")
            print(emit_fields(post_fields, "      "))
            print("    }),")
            print("  },")
            special_post_forms.append((page_key, post_fields))

    print("}")
    print()
    print("-- Same field sets as the dedicated per-page POST routes above, but as")
    print("-- bare form validators (not full route tables) for splicing into the")
    print("-- generic \"index php post\" route's form_schemas - see the comment")
    print("-- further up about why query-string-style /index.php?title=Special:X")
    print("-- URLs need this too, not just /index.php/Special:X path-style ones.")
    print("local mw_special_post_forms = {")
    for page_key, post_fields in special_post_forms:
        label = label_for(page_key)
        print(f"  -- {page_key}")
        print(f"  T.object({{")
        print(emit_fields(post_fields, "    "))
        print("  }),")
    print("}")


if __name__ == "__main__":
    main()

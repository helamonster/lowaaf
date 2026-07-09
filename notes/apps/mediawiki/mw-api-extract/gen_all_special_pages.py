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


def _tokenize(name):
    # Splits on camelCase boundaries and non-alnum separators, e.g.
    # "wpContextTitle" -> {"wp", "context", "title"}, "log-comment" ->
    # {"log", "comment"}. Whole-word hint matching against these tokens
    # (instead of raw substring containment against the full lowercased
    # name) avoids accidental collisions like "wpContextTitle" matching the
    # "text" hint purely because "con-TEXT-title" contains those 4 letters
    # in a row - confirmed live: this gave a single-line MediaWiki title
    # input (HTMLForm 'type' => 'text', 'size' => 60 - not a textarea) a 1MB
    # cap meant for genuine free-text fields.
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return set(re.split(r"[^A-Za-z0-9]+", spaced.lower())) - {""}


def cap_for(name, spec):
    tokens = _tokenize(name)
    for hint, cap in LONG_FIELD_HINTS.items():
        if hint in tokens:
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
    # (page_key, page_name, get_extra_fields) for every page that has extra
    # GET-navigable fields AND isn't one of the 16 already hand-tuned in
    # mw_special_pages (ALREADY_HAS_GET_ROUTE) - those already have precise,
    # title-gated coverage for the ?title=Special:X query-string form via
    # index_query_check; this list extends that same mechanism
    # (mw_bulk_special_query_pages, reassigned into a forward-declared local
    # - see mediawiki.lua) to the remaining pages. Confirmed live missing
    # for Special:PrefixIndex's prefix/namespace/hideredirects/stripprefix.
    special_query_pages = []

    for page_key in sorted(data.keys()):
        entry = data[page_key]
        label = label_for(page_key)
        fields = entry.get("fields") or {}
        method = entry["method"]
        page_name = f"Special:{page_key}"

        has_get_already = page_key.lower() in ALREADY_HAS_GET_ROUTE
        # redirect_passthrough fields are GET-navigable query params (e.g.
        # returnto/returntoquery); form_fields/heuristic fields are POST-submitted.
        #
        # heuristic fields are also GET-navigable, though, and get exposed
        # BOTH ways below: they come from scanning $request->getVal()/
        # getBool()/getInt() calls directly, and WebRequest's getters don't
        # care which HTTP method supplied the value - unlike a real
        # HTMLForm's declared fields (form_fields, which assume a POST
        # submission with its own CSRF/wasPosted() gate), a heuristic-
        # scanned page reading e.g. `prefix`/`namespace`/`hideredirects` via
        # getVal() will happily accept those same names on a plain GET too.
        # Confirmed live: SpecialPrefixIndex (extends SpecialAllPages, a
        # GET-navigable listing page already hand-tuned in
        # ALREADY_HAS_GET_ROUTE) - browsing it via GET with
        # prefix=/namespace=/hideredirects=/stripprefix= got denied because
        # those fields only existed in the generated POST form, never in the
        # page's own GET route.
        get_extra_fields = dict(fields) if method == "redirect_passthrough" else {}
        if method == "heuristic":
            get_extra_fields.update(fields)
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
            if get_extra_fields:
                special_query_pages.append((page_key, page_name, get_extra_fields))

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
    print()
    print("-- Reassigns the forward-declared local from earlier in this file (NOT")
    print("-- `local` here - see the comment next to its declaration, right after")
    print("-- mw_special_pages, for why). Same {label, titles, fields} shape as")
    print("-- mw_special_pages, covering the query-string ?title=Special:X form for")
    print("-- every page below that ISN'T one of the 16 already hand-tuned there.")
    print("mw_bulk_special_query_pages = {")
    for page_key, page_name, get_extra_fields in special_query_pages:
        label = label_for(page_key)
        print(f"  {{ label = {lua_str(label)}, titles = {{ {lua_str(page_name)} }}, fields = {{")
        print(emit_fields(get_extra_fields, "    "))
        print("  } },")
    print("}")


if __name__ == "__main__":
    main()

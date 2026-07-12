#!/usr/bin/env python3
"""
Generates rootfs/etc/openresty/waf/apps/mediawiki/special_pages.lua: dedicated
routes for all 132 core Special: pages from special-fields.json, reconciled
with the 16 pages already precisely hand-tuned as GET routes in
mediawiki.lua's own mw_special_pages (AllPages, ListUsers,
RecentChangesLinked, Redirect, ProtectedTitles, Log, ActiveUsers,
ComparePages, WhatLinksHere, LinkSearch, MIMESearch, NewPages, MergeHistory,
PagesWithProp, Contributions, AllMessages) - these keep their existing GET
route untouched; this script only adds a POST route for them if real
submitted fields were found (e.g. MergeHistory).

Every page gets a dedicated GET route (query = idx_common, plus any
redirect-passthrough or heuristic-scanned fields; no_body = true) unless it
already has one from the hand-tuned set above. Pages with real submitted
fields (form_fields or heuristic method) additionally get a POST route with
those fields as a form schema. Pages with nothing found (query_page_standard
/ none / empty redirect_passthrough) get ONLY the bare GET route.

Replaces gen_all_special_pages.py + integrate_all_special_pages.py. Two
differences from the old splice-based version:

  1. Writes a complete, standalone Lua module (wholesale overwrite, no
     markers) instead of splicing generated fragments into mediawiki.lua.
     Since the dedicated GET routes' query schemas need idx_common
     (mediawiki.lua's own hand-written common-fields table, not visible
     inside a separate required module), this module returns a FACTORY
     FUNCTION - require(...)(idx_common) - rather than a flat table.

  2. Dedups the field-table repetition that used to exist across FOUR
     places (each page's fields got printed as literal Lua text in its
     dedicated route AND in mw_special_post_forms/mw_bulk_special_query_pages
     separately - 2-4x the same field list): one page_get_fields / one
     page_post_validators table, each page's fields/validator built once and
     referenced by every consumer instead of re-emitted.

Usage: python3 gen_special_pages.py
"""
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root, lua_str, field_key  # noqa: E402

ROOT = find_repo_root(SCRIPT_DIR)
OUT_PATH = os.path.join(ROOT, "rootfs/etc/openresty/waf/apps/mediawiki/special_pages.lua")

# Already have a precisely hand-tuned GET route via mw_special_pages / the
# dedicated allmessages_route (both in mediawiki.lua itself) - don't
# generate a duplicate GET route for these. MediaWiki case-folds special
# page names before resolving them (see SpecialPageFactory::resolveAlias()),
# so CORE_LIST's internal key casing (e.g. "Allpages", "Whatlinkshere")
# doesn't necessarily match what's in a real URL - compare case-
# insensitively rather than trying to guess which casing is "the real one".
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


def label_for(page_key):
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

    # Two page-keyed catalogs, each page's field data written ONCE - every
    # consumer below (dedicated routes, mw_special_post_forms,
    # mw_bulk_special_query_pages) references these instead of re-emitting
    # the same field list. page_post_fields holds full T.object(...)
    # validators (not raw field tables) since nothing downstream needs the
    # raw fields for POST - unlike GET, which still needs to merge each
    # page's raw fields with idx_common (only available in mediawiki.lua
    # itself, hence this whole module being a factory function).
    page_get_fields = []    # (page_key, label, fields dict)
    page_post_fields = []   # (page_key, label, fields dict)

    route_entries = []       # pre-rendered Lua route table entries, referencing the above by label
    query_page_entries = []  # (page_key, page_name, label) for pages needing mw_bulk_special_query_pages coverage

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
        # BOTH ways: they come from scanning $request->getVal()/getBool()/
        # getInt() calls directly, and WebRequest's getters don't care which
        # HTTP method supplied the value - unlike a real HTMLForm's declared
        # fields (form_fields, which assume a POST submission with its own
        # CSRF/wasPosted() gate), a heuristic-scanned page reading e.g.
        # `prefix`/`namespace`/`hideredirects` via getVal() will happily
        # accept those same names on a plain GET too. Confirmed live:
        # SpecialPrefixIndex (extends SpecialAllPages, a GET-navigable
        # listing page already hand-tuned in ALREADY_HAS_GET_ROUTE) -
        # browsing it via GET with prefix=/namespace=/hideredirects=/
        # stripprefix= got denied because those fields only existed in the
        # generated POST form, never in the page's own GET route.
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

        header = (f"  -- {page_key} ({entry.get('class')}, extends={entry.get('extends')}, method={method})"
                  + (f" -- {entry['file']}" if entry.get("file") else ""))

        if not has_get_already:
            lines = [header, "  {"]
            lines.append(f"    name    = \"index php special {label}\",")
            lines.append(f"    method  = \"GET\",")
            lines.append(f"    path    = [[(?i)^/index\\.php/{page_name}(?:/.*)?$]],")
            if get_extra_fields:
                lines.append(f"    query   = T.object(merge(idx_common, page_get_fields.{field_key(label)})),")
            else:
                lines.append(f"    query   = T.object(idx_common),")
            lines.append("    no_body = true,")
            lines.append("  },")
            route_entries.append("\n".join(lines))
            if get_extra_fields:
                page_get_fields.append((page_key, label, get_extra_fields))
                query_page_entries.append((page_key, page_name, label))

        if post_fields:
            lines = [header, "  {"]
            lines.append(f"    name    = \"index php special {label} post\",")
            lines.append(f"    method  = \"POST\",")
            lines.append(f"    path    = [[(?i)^/index\\.php/{page_name}(?:/.*)?$]],")
            lines.append("    content_types = { \"application/x-www-form-urlencoded\", \"multipart/form-data\" },")
            if page_key in MAX_BODY_OVERRIDES:
                lines.append(f"    max_body = {MAX_BODY_OVERRIDES[page_key]},")
            lines.append(f"    form    = page_post_validators.{field_key(label)},")
            lines.append("  },")
            route_entries.append("\n".join(lines))
            page_post_fields.append((page_key, label, post_fields))

    out = []
    out.append("-- Generated by gen_special_pages.py from special-fields.json - do not")
    out.append("-- hand-edit, re-run the generator.")
    out.append("--")
    out.append("-- A factory function, not a flat module table: the dedicated GET routes'")
    out.append("-- query schemas need idx_common (mediawiki.lua's own hand-written common-")
    out.append("-- fields table), which isn't visible inside this separately-required file -")
    out.append("-- so mediawiki.lua does")
    out.append("-- `local special_pages = require(\"waf.apps.mediawiki.special_pages\")(idx_common)`")
    out.append("-- instead of a plain require().")
    out.append("return function(idx_common)")
    out.append("local T = require \"waf.types\"")
    out.append("")
    out.append("-- Shallow-merges one or more {key=validator} tables into a new table; later")
    out.append("-- tables' keys win on conflict.")
    out.append("local function merge(...)")
    out.append("  local out = {}")
    out.append("  for _, t in ipairs({...}) do")
    out.append("    for k, v in pairs(t) do out[k] = v end")
    out.append("  end")
    out.append("  return out")
    out.append("end")
    out.append("")
    out.append("-- Each page's raw GET-navigable extra fields, written once - referenced by")
    out.append("-- both its own dedicated route below and mw_bulk_special_query_pages (the")
    out.append("-- ?title=Special:X query-string form's title-gated coverage).")
    out.append("local page_get_fields = {")
    for page_key, label, fields in page_get_fields:
        out.append(f"  -- {page_key}")
        out.append(f"  {field_key(label)} = {{")
        out.append(emit_fields(fields, "    "))
        out.append("  },")
    out.append("}")
    out.append("")
    out.append("-- Each page's POST form, pre-built as a validator (not raw fields, unlike")
    out.append("-- page_get_fields above - nothing downstream needs the raw POST fields")
    out.append("-- separately) - referenced by both its own dedicated route below and")
    out.append("-- mw_special_post_forms (the generic \"index php post\" catch-all's coverage")
    out.append("-- for query-string-style /index.php?title=Special:X POSTs, which the")
    out.append("-- dedicated /index.php/Special:X path-style route above can never see -")
    out.append("-- confirmed live via Special:EditWatchlist/raw's wpTitles getting rejected.")
    out.append("")
    out.append("local page_post_validators = {")
    for page_key, label, fields in page_post_fields:
        out.append(f"  -- {page_key}")
        out.append(f"  {field_key(label)} = T.object({{")
        out.append(emit_fields(fields, "    "))
        out.append("  }),")
    out.append("}")
    out.append("")
    out.append("-- ==========================================================================")
    out.append("-- Dedicated routes for every core Special: page not already hand-tuned in")
    out.append("-- mediawiki.lua's own mw_special_pages.")
    out.append("-- ==========================================================================")
    out.append("local routes = {")
    for entry in route_entries:
        out.append(entry)
    out.append("}")
    out.append("")
    out.append("-- Same field sets as the dedicated per-page POST routes above (referenced,")
    out.append("-- not re-emitted) for splicing into the generic \"index php post\" route's")
    out.append("-- form_schemas.")
    out.append("local post_forms = {")
    for page_key, label, _fields in page_post_fields:
        out.append(f"  page_post_validators.{field_key(label)},  -- {page_key}")
    out.append("}")
    out.append("")
    out.append("-- Same {label, titles, fields} shape as mediawiki.lua's own mw_special_pages,")
    out.append("-- covering the ?title=Special:X query-string form for every page below that")
    out.append("-- isn't one of the 16 already hand-tuned there.")
    out.append("local query_pages = {")
    for page_key, page_name, label in query_page_entries:
        out.append(f"  {{ label = {lua_str(label)}, titles = {{ {lua_str(page_name)} }}, "
                    f"fields = page_get_fields.{field_key(label)} }},  -- {page_key}")
    out.append("}")
    out.append("")
    out.append("return { routes = routes, post_forms = post_forms, query_pages = query_pages }")
    out.append("end")

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"Wrote {OUT_PATH} ({len(route_entries)} routes, {len(page_post_fields)} POST forms, "
          f"{len(query_page_entries)} query-string-gated pages)")


if __name__ == "__main__":
    main()

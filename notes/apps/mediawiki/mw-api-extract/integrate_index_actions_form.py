#!/usr/bin/env python3
"""
Splices the generated index.php action=X POST form schemas (gen_index_actions_form.py)
into mediawiki.lua right after index_post_form, and switches the "index php
post" route from a single `form = index_post_form` to
`form_schemas = { index_post_form, table.unpack(mw_index_action_forms) }` so
core.lua tries every action's form in turn (route.form_schemas: "tries each
schema, passes if any matches").

Idempotent: safe to re-run after regenerating index-actions.json or tweaking
gen_index_actions_form.py.

Usage: python3 integrate_index_actions_form.py
"""
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_repo_root(start):
    d = start
    while d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, "rootfs", "etc", "openresty", "waf")):
            return d
        d = os.path.dirname(d)
    raise RuntimeError("could not find repo root above " + start)


ROOT = _find_repo_root(SCRIPT_DIR)
LUA_PATH = os.path.join(ROOT, "rootfs/etc/openresty/waf/apps/mediawiki.lua")

BLOCK_HEADER = "-- ---------------------------------------------------------------------------\n-- index.php action=X POST forms"
END_MARKER_AFTER_INDEX_POST_FORM = "})\n\n"
OLD_FORM_LINE = "      form  = index_post_form,\n"
# Lua table constructors only let the LAST element expand via table.unpack()
# (...)  - an earlier table.unpack() call in the middle just contributes its
# first return value. mw_index_action_forms and mw_special_post_forms both
# need full expansion, so this can't be a single `{ a, table.unpack(b),
# table.unpack(c) }` literal; merge them at runtime instead. mw_special_post_
# forms (the 132 Special: pages' own POST fields, from gen_all_special_pages.
# py) has to be included here too, not just reachable via the dedicated
# "index php special X post" path-style routes - those only match
# /index.php/Special:X URLs, never /index.php?title=Special:X (query-string
# style, which is what a self-submitting HTMLForm actually generates -
# confirmed live via Special:EditWatchlist/raw's wpTitles getting rejected).
NEW_FORM_LINES = (
    "      form_schemas = (function()\n"
    "        local fs = { index_post_form }\n"
    "        for _, f in ipairs(mw_index_action_forms) do fs[#fs + 1] = f end\n"
    "        for _, f in ipairs(mw_special_post_forms) do fs[#fs + 1] = f end\n"
    "        return fs\n"
    "      end)(),\n"
)
OLD_NEW_FORM_LINES = "      form_schemas = { index_post_form, table.unpack(mw_index_action_forms) },\n"


def main():
    gen_proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, "gen_index_actions_form.py")],
        capture_output=True, text=True, check=True,
    )
    new_block = gen_proc.stdout

    src = open(LUA_PATH, encoding="utf-8").read()

    # 1) Insert/replace the action-forms block right after index_post_form.
    ipf_marker = "local index_post_form = T.object({"
    if ipf_marker not in src:
        print("ERROR: could not find index_post_form", file=sys.stderr)
        sys.exit(1)
    ipf_idx = src.index(ipf_marker)
    insert_idx = src.index(END_MARKER_AFTER_INDEX_POST_FORM, ipf_idx) + len(END_MARKER_AFTER_INDEX_POST_FORM)

    if BLOCK_HEADER in src:
        # Already integrated once - replace the existing block instead of
        # inserting a second copy. Bounded by the header through the closing
        # "}\n" of mw_index_action_forms specifically - NOT "the next blank
        # line", which used to skip clean over the entire (blank-line-free)
        # Special: pages array that follows and delete it too.
        block_start = src.index(BLOCK_HEADER)
        list_marker = "local mw_index_action_forms = {\n"
        list_start = src.index(list_marker, block_start)
        list_end = src.index("\n}\n", list_start) + len("\n}\n")
        src = src[:block_start] + new_block + src[list_end:]
    else:
        src = src[:insert_idx] + new_block + "\n" + src[insert_idx:]

    # 2) Point "index php post" at every action form AND every Special: page's
    #    own POST form, not just index_post_form.
    if OLD_FORM_LINE in src:
        src = src.replace(OLD_FORM_LINE, NEW_FORM_LINES, 1)
    elif OLD_NEW_FORM_LINES in src:
        # Previous run's version (before mw_special_post_forms existed).
        src = src.replace(OLD_NEW_FORM_LINES, NEW_FORM_LINES, 1)
    elif NEW_FORM_LINES not in src:
        print("ERROR: could not find the 'index php post' route's form line "
              "(none of the original, the previous, or the current integrated form)", file=sys.stderr)
        sys.exit(1)

    open(LUA_PATH, "w", encoding="utf-8").write(src)
    print(f"Integrated {new_block.count('local action_')} index.php action forms into {LUA_PATH}")


if __name__ == "__main__":
    main()

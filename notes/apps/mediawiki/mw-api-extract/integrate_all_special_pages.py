#!/usr/bin/env python3
"""
Replaces the Special: page bulk-route block with the current output of
gen_all_special_pages.py (a single `local mw_bulk_special_routes = {...}`
array, to stay well under Lua's 200-local-per-chunk ceiling), and restructures
the routes table to splice that array in via table.insert rather than listing
each route by name (which is what originally blew past the 200-local limit:
~160 generated routes each got their own named local).

Idempotent: safe to re-run after regenerating special-fields.json or tweaking
gen_all_special_pages.py.

Usage: python3 integrate_all_special_pages.py
"""
import os
import re
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

BLOCK_START_MARKER = "-- Dedicated routes for every core Special: page (Tier 6, full coverage)."
BLOCK_HEADER = "-- ==========================================================================\n" + BLOCK_START_MARKER
# Tolerant of 0-2 blank lines before the load.php header - other integrators
# (gen_index_actions_form.py's output, in particular) don't always leave
# exactly one blank line before whatever section follows them, and an exact
# literal match here previously caused this script to report "not found" on
# an otherwise-intact file.
END_MARKER_RE = re.compile(
    r"\n*-- -+\n-- load\.php GET query schema"
)


def main():
    gen_proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, "gen_all_special_pages.py")],
        capture_output=True, text=True, check=True,
    )
    new_block = gen_proc.stdout.rstrip("\n")

    src = open(LUA_PATH, encoding="utf-8").read()

    # 1) Replace the special-pages declarations block (whatever form it's
    #    currently in - either the very first hand-picked-12 version, or a
    #    previous run of this same generator) with the fresh array literal.
    # Self-healing: if the block is missing entirely (e.g. another
    # integrator's buggy re-run clobbered it - has happened), fall back to
    # inserting fresh content right before END_MARKER instead of erroring out.
    if BLOCK_HEADER in src:
        start_idx = src.index(BLOCK_HEADER)
        end_m = END_MARKER_RE.search(src, start_idx)
        if not end_m:
            print("ERROR: found the special-pages block start but not the end marker", file=sys.stderr)
            sys.exit(1)
        src = src[:start_idx] + new_block + src[end_m.start():]
    elif END_MARKER_RE.search(src):
        print("WARNING: special-pages block was missing entirely - reinserting", file=sys.stderr)
        end_idx = END_MARKER_RE.search(src).start()
        src = src[:end_idx] + "\n\n" + new_block + src[end_idx:]
    else:
        print("ERROR: could not find the special-pages declarations block "
              "start OR the end marker - can't safely reinsert", file=sys.stderr)
        sys.exit(1)

    # 2) Restructure the routes table: pull the routes = { ... } literal out
    #    into an intermediate `mw_static_routes_pre` / `mw_static_routes_post`
    #    split around allmessages_route / the "index php get" catch-all, then
    #    splice mw_bulk_special_routes between them via table.insert (a Lua
    #    table constructor can't splice a variable-length array into the
    #    middle of a list literal - table.unpack() there would only keep its
    #    first return value unless it's the very last element).
    if "local mw_routes = (function()" not in src:
        routes_open = "\n  routes = {\n"
        idx = src.index(routes_open)
        depth = 0
        i = idx + len(routes_open) - 2  # position of the "{"
        while True:
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        routes_body = src[idx + len(routes_open):i]  # content between "{" and matching "}"

        # Split at the allmessages_route / "index php get" boundary.
        anchor = "    allmessages_route,\n"
        anchor_idx = routes_body.index(anchor) + len(anchor)
        split_marker = '    {\n      name    = "index php get",'
        split_idx = routes_body.index(split_marker)

        pre = routes_body[:anchor_idx]
        post = routes_body[split_idx:]

        mw_routes_fn = (
            "local mw_routes = (function()\n"
            "  local rs = {\n" + pre + "  }\n"
            "  for _, r in ipairs(mw_bulk_special_routes) do rs[#rs + 1] = r end\n"
            "  for _, r in ipairs({\n" + post + "  }) do rs[#rs + 1] = r end\n"
            "  return rs\n"
            "end)()\n\n"
        )

        # Insert mw_routes construction right before "return {", and change
        # the routes field to reference it instead of a literal.
        return_idx = src.index("return {\n")
        src = src[:return_idx] + mw_routes_fn + src[return_idx:]

        # Re-locate and replace the (now-shifted) routes = { ... } literal
        # with a plain reference to mw_routes.
        idx2 = src.index(routes_open, return_idx + len(mw_routes_fn))
        depth = 0
        i2 = idx2 + len(routes_open) - 2
        while True:
            c = src[i2]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i2 += 1
        # src[i2 + 1:] begins right after the routes table's closing "}",
        # which retains the original field-separating comma - don't add
        # another one here or the table literal gets a duplicate comma.
        src = src[:idx2] + "\n  routes = mw_routes\n" + src[i2 + 1:]

    open(LUA_PATH, "w", encoding="utf-8").write(src)
    print("Integrated the Special: page bulk-routes array and restructured the routes table.")


if __name__ == "__main__":
    main()

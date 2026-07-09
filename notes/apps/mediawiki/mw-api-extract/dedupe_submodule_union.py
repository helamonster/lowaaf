#!/usr/bin/env python3
"""
One-off cleanup: collapses repeated `local mw_query_submodule_fields_union = {}`
blocks (left behind by a since-fixed bug in integrate_api_tiers.py, where a
too-narrow end marker let every re-run pile up another copy instead of
replacing the last one) down to a single copy.

Usage: python3 dedupe_submodule_union.py
"""
import os
import re

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

BLOCK_RE = re.compile(
    r"local mw_query_submodule_fields_union = \{\}\n"
    r"for _, kind_fields in pairs\(mw_query_submodules\) do\n"
    r"  for _, fields in pairs\(kind_fields\) do\n"
    r"    mw_query_submodule_fields_union = merge\(mw_query_submodule_fields_union, fields\)\n"
    r"  end\n"
    r"end\n\n?"
)


def main():
    src = open(LUA_PATH, encoding="utf-8").read()
    matches = list(BLOCK_RE.finditer(src))
    if len(matches) <= 1:
        print(f"Nothing to do ({len(matches)} copies found).")
        return

    first = matches[0]
    last = matches[-1]
    kept = src[first.start():first.end()]
    src = src[:first.start()] + kept + src[last.end():]
    open(LUA_PATH, "w", encoding="utf-8").write(src)
    print(f"Collapsed {len(matches)} copies down to 1.")


if __name__ == "__main__":
    main()

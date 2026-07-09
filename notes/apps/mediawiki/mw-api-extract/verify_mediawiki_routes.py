#!/usr/bin/env python3
"""
Sanity-checks the generated route table in mediawiki.lua:
  1. no two routes share the same `name`
  2. no orphaned `local X_route`/`local X_form` declarations left over from
     earlier generator passes (declared but never referenced in the routes
     table - dead code from a prior integration step that got superseded)
  3. Special: page coverage - how many of the pages in special-fields.json
     ended up with a dedicated "index php special X" route

Usage: python3 verify_mediawiki_routes.py
"""
import json
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
FIELDS_PATH = os.path.join(SCRIPT_DIR, "special-fields.json")


def main():
    src = open(LUA_PATH, encoding="utf-8").read()
    ok = True

    names = re.findall(r'name\s*=\s*"([^"]*)"', src)
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        ok = False
        print(f"DUPLICATE route names ({len(dupes)}):")
        for n in dupes:
            print(f"  - {n}")
    else:
        print(f"no duplicate route names ({len(names)} routes)")

    declared = set(re.findall(r"^local (\w+_(?:route|form))\s*=", src, re.MULTILINE))
    orphaned = sorted(n for n in declared if src.count(n) == 1)
    if orphaned:
        ok = False
        print(f"ORPHANED locals, declared but never referenced ({len(orphaned)}):")
        for n in orphaned:
            print(f"  - {n}")
    else:
        print(f"no orphaned route/form locals ({len(declared)} named locals checked)")

    if os.path.exists(FIELDS_PATH):
        with open(FIELDS_PATH) as f:
            core_pages = set(json.load(f).keys())
        covered = {
            m.lower() for m in re.findall(r'name\s*=\s*"index php special (\w+?)(?: post)?"', src)
        }
        # special_page_route(label, ...) builds its `name` by concatenation
        # (`"index php special " .. label`), so the literal-string scan above
        # misses these - pick up the label argument directly instead.
        covered |= {
            m.lower() for m in re.findall(r'special_page_route\(\s*"(\w+)"', src)
        }
        labels = {re.sub(r"[^a-z0-9]", "", p.lower()) for p in core_pages}
        missing = sorted(labels - covered)
        print(f"Special: page coverage: {len(labels) - len(missing)}/{len(labels)}")
        if missing:
            print(f"  missing dedicated routes for: {', '.join(missing)}")

    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

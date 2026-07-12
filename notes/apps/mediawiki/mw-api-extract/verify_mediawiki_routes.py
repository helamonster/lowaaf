#!/usr/bin/env python3
"""
Sanity-checks the real, assembled mediawiki.lua route table (not its source
text - see below for why that distinction matters):
  1. no two routes share the same `name`
  2. Special: page coverage - how many of the pages in special-fields.json
     ended up with a dedicated "index php special X" route

Loads the app for real (`resty -e 'require "waf.apps.mediawiki"...'`) and
inspects app.routes directly, rather than regexing mediawiki.lua's source
text for `name = "..."` patterns. The old text-regex approach couldn't tell
generated Lua from hand-written Lua apart, and by definition can't see
anything defined in a separately `require`d module (api_schema.lua/
special_pages.lua/edit_forms.lua) - actually loading the app sidesteps both
problems entirely and reflects real runtime behavior, not an approximation
of it.

Doesn't check for "orphaned locals declared but never referenced" (the old
version did) - that failure mode was specific to the marker-splicing
approach this pipeline no longer uses: a too-narrow end-marker could leave a
previous run's now-unreferenced local sitting in mediawiki.lua's text
forever. Every generated file is wholesale-overwritten from scratch now, so
there's no mechanism left that could produce a stale local to begin with.

Usage: python3 verify_mediawiki_routes.py
"""
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root  # noqa: E402

ROOT = find_repo_root(SCRIPT_DIR)
OPENRESTY_DIR = os.path.join(ROOT, "rootfs/etc/openresty")
FIELDS_PATH = os.path.join(SCRIPT_DIR, "special-fields.json")

LUA_SNIPPET = '''
local cjson = require "cjson.safe"
local app = require "waf.apps.mediawiki"
local names = {}
for _, r in ipairs(app.routes) do
  names[#names + 1] = r.name or "?"
end
io.write(cjson.encode(names))
'''


def load_route_names():
    proc = subprocess.run(
        ["resty", "-I", OPENRESTY_DIR, "-e", LUA_SNIPPET],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print("ERROR: could not load waf.apps.mediawiki:", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        sys.exit(1)
    return json.loads(proc.stdout)


def main():
    ok = True
    names = load_route_names()

    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        ok = False
        print(f"DUPLICATE route names ({len(dupes)}):")
        for n in dupes:
            print(f"  - {n}")
    else:
        print(f"no duplicate route names ({len(names)} routes)")

    if os.path.exists(FIELDS_PATH):
        with open(FIELDS_PATH) as f:
            core_pages = set(json.load(f).keys())
        covered = set()
        for n in names:
            m = re.match(r"^index php special (\w+?)(?: post)?$", n)
            if m:
                covered.add(m.group(1).lower())
        labels = {re.sub(r"[^a-z0-9]", "", p.lower()) for p in core_pages}
        missing = sorted(labels - covered)
        print(f"Special: page coverage: {len(labels) - len(missing)}/{len(labels)}")
        if missing:
            ok = False
            print(f"  missing dedicated routes for: {', '.join(missing)}")

    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

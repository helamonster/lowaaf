#!/usr/bin/env python3
"""
Sanity-checks the real, assembled gitea.lua route table - loads the app for
real (`resty -e 'require "waf.apps.gitea"...'`) and inspects app.routes
directly, same approach as verify_mediawiki_routes.py and for the same
reason: reflects actual runtime behavior instead of an approximation of it.

Checks:
  1. no two routes share the same `name`
  2. the generated-route subset (name prefix "gitea api ", Phase 1 -
     everything gen_api_schema.py produces) count matches
     gitea-api-extracted.json's operation count exactly - every swagger
     operation produced exactly one route, none dropped/duplicated. Routes
     outside that subset are Phase 3's hand-written git-http/LFS routes
     ("gitea git "/"gitea lfs " prefixes) - reported, not asserted against,
     since they're not generated from gitea-api-extracted.json at all.

Usage: python3 verify_gitea_routes.py
"""
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root  # noqa: E402

ROOT = find_repo_root(SCRIPT_DIR)
OPENRESTY_DIR = os.path.join(ROOT, "rootfs/etc/openresty")
EXTRACTED_PATH = os.path.join(SCRIPT_DIR, "gitea-api-extracted.json")

LUA_SNIPPET = '''
local cjson = require "cjson.safe"
local app = require "waf.apps.gitea"
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
        print("ERROR: could not load waf.apps.gitea:", file=sys.stderr)
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

    generated_api = [n for n in names if n.startswith("gitea api ")]
    generated_web = [n for n in names if n.startswith("gitea web ")]
    hand_written = [n for n in names if not n.startswith("gitea api ") and not n.startswith("gitea web ")]

    if os.path.exists(EXTRACTED_PATH):
        with open(EXTRACTED_PATH) as f:
            expected = len(json.load(f)["operations"])
        if len(generated_api) != expected:
            ok = False
            print(f"ROUTE COUNT MISMATCH: {len(generated_api)} generated (Phase 1) routes, "
                  f"but gitea-api-extracted.json has {expected} operations")
        else:
            print(f"generated (Phase 1) route count matches extracted operation count ({expected})")
    else:
        print(f"(skipping Phase 1 route-count check - {EXTRACTED_PATH} not found)")

    print(f"generated (Phase 2 web UI) routes: {len(generated_web)}")
    print(f"hand-written routes (Phase 3 git-http/LFS): {len(hand_written)}")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

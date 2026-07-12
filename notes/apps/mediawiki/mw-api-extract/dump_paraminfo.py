#!/usr/bin/env python3
"""
Queries a running MediaWiki instance's action=paraminfo API for the fully-
resolved parameter set of every action and query submodule, in one request
(modules=main+** - a MediaWiki wildcard meaning "list main's own submodules,
i.e. every action=X, and recurse into each of THEIR submodules too", so
query's own prop=/list=/meta= submodules are included automatically).

This is live introspection, not static source parsing: PHP has already
evaluated any dynamic getAllowedParams() construction (e.g. the SearchApi
trait's buildCommonApiParams(), which a regex parser can't resolve) by the
time it responds, and the response includes real min/max/default bounds,
resolved enum values, wire prefixes, generator-eligibility, and post-
getFinalParams() injected fields (like a needsToken() module's csrf token)
that would otherwise need separate heuristics to detect. Reshapes the raw
API response (a flat list, keyed by nothing) into a dict keyed by each
module's `path` (e.g. "query+prefixsearch"), which gen_api_schema.py reads.

One real caveat (see gen_api_schema.py's own header): a handful of fields
are genuinely config/extension-dependent (e.g. search sort order, page
protection levels) - what THIS dump shows for those reflects the dumping
environment's specific config, not necessarily any other deployment's.
gen_api_schema.py cross-references extract_mediawiki_api.py's static
`dynamic_type_expr` detection to avoid baking those in as strict enums.

Usage: python3 dump_paraminfo.py [base-url]
Defaults to http://localhost:8889 (the Docker test stack - must be up first,
`bash tools.sh docker-test-up`).
"""
import json
import os
import sys
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(SCRIPT_DIR, "paraminfo.json")


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8889"
    url = f"{base}/api.php?action=paraminfo&modules=main%2B**&format=json"

    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)
    except Exception as e:
        print(f"ERROR: could not fetch {url}: {e}", file=sys.stderr)
        print("Is the Docker test stack up? (bash tools.sh docker-test-up)", file=sys.stderr)
        sys.exit(1)

    raw_modules = data.get("paraminfo", {}).get("modules", [])
    if not raw_modules:
        print(f"ERROR: no modules in paraminfo response from {url} "
              f"(got keys: {list(data.keys())})", file=sys.stderr)
        sys.exit(1)

    modules = {}
    for m in raw_modules:
        path = m.get("path")
        if not path:
            continue
        modules[path] = m

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"api_url": f"{base}/api.php", "modules": modules}, f, indent=2, sort_keys=True)

    by_group = {}
    for m in modules.values():
        by_group.setdefault(m.get("group", "?"), 0)
        by_group[m.get("group", "?")] += 1
    print(f"Wrote {OUT_PATH} ({len(modules)} modules: " +
          ", ".join(f"{g}={n}" for g, n in sorted(by_group.items())) + ")")


if __name__ == "__main__":
    main()

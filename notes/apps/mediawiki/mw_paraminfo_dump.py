#!/usr/bin/env python3
import argparse
import json
import sys
import urllib.parse
import urllib.request


def api_get(api_url, params):
    params = dict(params)
    params.setdefault("format", "json")
    url = api_url + "?" + urllib.parse.urlencode(params, doseq=True)

    with urllib.request.urlopen(url) as r:
        return json.loads(r.read().decode("utf-8"))


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def get_modules(api_url, modules):
    out = []
    for chunk in chunks(modules, 50):
        data = api_get(api_url, {
            "action": "paraminfo",
            "modules": "|".join(chunk),
            "helpformat": "none",
        })
        out.extend(data.get("paraminfo", {}).get("modules", []))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url", help="Example: http://localhost:8889/")
    ap.add_argument("-o", "--output", default="mediawiki-api-paraminfo.json")
    args = ap.parse_args()

    api_url = args.base_url.rstrip("/") + "/api.php"

    # "main" gives global params. "query+**" recursively expands all query submodules.
    # "*" expands all top-level action/format modules.
    seeds = ["main", "*", "query+**"]

    modules = get_modules(api_url, seeds)

    # Some MediaWiki versions return expanded modules directly; others may need names re-requested.
    names = sorted({m.get("path") or m.get("name") for m in modules if m.get("name")})
    more = get_modules(api_url, names)
    by_name = {}

    for m in modules + more:
        key = m.get("path") or m.get("name")
        if key:
            by_name[key] = m

    result = {
        "api_url": api_url,
        "module_count": len(by_name),
        "modules": dict(sorted(by_name.items())),
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)

    print(f"Wrote {args.output}")
    print(f"Modules found: {len(by_name)}")

    for name, mod in sorted(by_name.items()):
        print(f"\n[{name}]")
        for p in mod.get("parameters", []):
            pname = p.get("name")
            ptype = p.get("type")
            required = " required" if p.get("required") else ""
            multi = " multi" if p.get("multi") else ""
            default = f" default={p.get('default')!r}" if "default" in p else ""
            print(f"  - {pname}: type={ptype!r}{required}{multi}{default}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)



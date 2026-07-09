#!/usr/bin/env python3
"""Prints the exact CORE_LIST keys (real MediaWiki casing) alongside our
special-fields.json entries, to catch any casing mismatches."""
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ALREADY_HAS_GET_ROUTE_OLD_GUESS = {
    "AllPages", "ListUsers", "RecentChangesLinked", "Redirect", "ProtectedTitles",
    "Log", "ActiveUsers", "ComparePages", "WhatLinksHere", "LinkSearch",
    "MIMESearch", "NewPages", "MergeHistory", "PagesWithProp", "Contributions",
    "AllMessages",
}


def main():
    with open(os.path.join(SCRIPT_DIR, "special-fields.json")) as f:
        data = json.load(f)

    print("All exact CORE_LIST keys:")
    for k in sorted(data.keys()):
        print(" ", k)
    print()

    print("Casing mismatches against my hand-typed exclusion set:")
    real_keys_lower = {k.lower(): k for k in data.keys()}
    for guess in sorted(ALREADY_HAS_GET_ROUTE_OLD_GUESS):
        real = real_keys_lower.get(guess.lower())
        if real is None:
            print(f"  {guess}: NOT FOUND AT ALL")
        elif real != guess:
            print(f"  {guess} -> real key is {real!r}")
        else:
            print(f"  {guess}: OK (matches)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Summarizes the upgraded special-fields.json extraction: method distribution
and a spot-check of specific pages."""
import json
import os
from collections import Counter

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

SPOT_CHECK = ["Block", "MergeHistory", "ChangeContentModel", "ChangePassword",
              "ProtectPage", "CreateAccount", "Upload", "Wantedpages", "Version",
              "DeletePage"]


def main():
    with open(os.path.join(SCRIPT_DIR, "special-fields.json")) as f:
        data = json.load(f)

    methods = Counter(v["method"] for v in data.values())
    print("Method distribution:", dict(methods))
    print()

    for page in SPOT_CHECK:
        entry = data.get(page)
        if not entry:
            print(f"{page}: NOT FOUND")
            continue
        print(f"{page} ({entry['class']}, extends={entry.get('extends')}, method={entry['method']}):")
        print(f"  {list(entry['fields'].keys())}")
        print()


if __name__ == "__main__":
    main()

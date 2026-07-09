#!/usr/bin/env python3
"""Prints heuristic candidate fields for a given list of Special: pages,
from mw-api-extract/special-fields.json."""
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PRIORITY = [
    "Upload", "Block", "Unblock", "Movepage", "DeletePage", "Userrights",
    "ChangePassword", "ProtectPage", "Import", "Export", "Undelete",
    "EditPage", "Preferences", "Emailuser", "RevisionDelete", "MergeHistory",
    "BlockList", "ChangeContentModel", "CreateAccount",
]


def main():
    with open(os.path.join(SCRIPT_DIR, "special-fields.json")) as f:
        data = json.load(f)

    for page in PRIORITY:
        if page not in data:
            print(f"{page}: NOT FOUND")
            continue
        entry = data[page]
        print(f"{page} ({entry['class']}):")
        print(f"  {entry['candidate_fields']}")
        print()


if __name__ == "__main__":
    main()

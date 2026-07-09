#!/usr/bin/env python3
"""Verifies the API module extraction still looks correct after the
return-statement-detection fix (no suspicious param names, known modules
still have their expected field counts)."""
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

EXPECTED_MIN_PARAMS = {
    "login": 4, "allusers": 14, "edit": 27, "delete": 8, "move": 9,
    "options": 6, "revisions": 20, "search": 6, "block": 20,
}


def main():
    with open(os.path.join(SCRIPT_DIR, "api-params.json")) as f:
        data = json.load(f)

    bad = []
    for k, v in data.items():
        for pname in v["params"]:
            if "::" in pname or pname.startswith("$") or "__DYNAMIC" in pname:
                bad.append((k, pname))
    print("Suspicious param names (should be empty):", bad)
    print()

    for key, min_count in EXPECTED_MIN_PARAMS.items():
        actual = len(data[key]["params"])
        status = "OK" if actual >= min_count else "REGRESSION"
        print(f"{key}: {actual} params (expected >= {min_count}) -> {status}")


if __name__ == "__main__":
    main()

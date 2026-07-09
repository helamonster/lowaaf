#!/usr/bin/env python3
"""Debug why SpecialBlock's getFormFields() wasn't parsed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from extract_mediawiki_api import extract_method_body, parse_return_array, find_default_mw_src, find_last_top_level_return

mw_src = find_default_mw_src()
path = os.path.join(mw_src, "includes/Specials/SpecialBlock.php")
src = open(path, encoding="utf-8", errors="replace").read()

body = extract_method_body(src, "getFormFields")
print(f"Body length: {len(body)} chars")

ret_span = find_last_top_level_return(body)
print("find_last_top_level_return ->", ret_span)
if ret_span:
    start, end = ret_span
    ret_expr = body[start:end].strip()
    print("ret_expr (first 100):", repr(ret_expr[:100]))
    print("ret_expr (last 100):", repr(ret_expr[-100:]))

log = []
arr = parse_return_array(body, "block", log)
print("parse_return_array result type:", type(arr))
if isinstance(arr, dict):
    print("Fields found:", sorted(arr.keys()))
print("Log entries:", len(log))
for entry in log:
    print(" -", entry)

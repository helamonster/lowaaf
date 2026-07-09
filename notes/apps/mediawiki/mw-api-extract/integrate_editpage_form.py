#!/usr/bin/env python3
"""
Replaces the hand-maintained `local index_post_form = T.object({...})` block
in mediawiki.lua with the current output of gen_editpage_form.py.

Idempotent: safe to re-run after regenerating editpage-fields.json or
tweaking gen_editpage_form.py.

Usage: python3 integrate_editpage_form.py
"""
import os
import subprocess
import sys

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

START_MARKER = "local index_post_form = T.object({\n"
END_MARKER = "})\n"


def main():
    gen_proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, "gen_editpage_form.py")],
        capture_output=True, text=True, check=True,
    )
    new_block = gen_proc.stdout

    src = open(LUA_PATH, encoding="utf-8").read()

    if START_MARKER not in src:
        print("ERROR: could not find index_post_form start marker", file=sys.stderr)
        sys.exit(1)
    start_idx = src.index(START_MARKER)
    end_idx = src.index(END_MARKER, start_idx) + len(END_MARKER)

    # Also swallow the preceding hand-written comment block (bounded above by
    # the blank line after the previous section) so it's fully replaced by
    # the generated header rather than leaving a stale doc-comment in front
    # of freshly generated content.
    comment_marker = "-- ---------------------------------------------------------------------------\n-- index.php POST form schema"
    if comment_marker in src and src.index(comment_marker) < start_idx:
        start_idx = src.index(comment_marker)

    src = src[:start_idx] + new_block + src[end_idx:]
    open(LUA_PATH, "w", encoding="utf-8").write(src)
    print(f"Integrated index_post_form ({new_block.count(chr(10))} lines) into {LUA_PATH}")


if __name__ == "__main__":
    main()

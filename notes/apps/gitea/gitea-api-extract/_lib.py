"""
Shared helpers for the Gitea WAF extraction/generation pipeline.

Same shape as notes/apps/mediawiki/mw-api-extract/_lib.py (find_repo_root,
lua_str, field_key) - not shared across apps, each app's extractor stays
self-contained, matching the current layout.
"""
import os
import re

LUA_RESERVED = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while",
}


def find_repo_root(start):
    """Walks upward from `start` looking for a rootfs/etc/openresty/waf marker
    directory, rather than assuming a fixed relative depth."""
    d = start
    while d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, "rootfs", "etc", "openresty", "waf")):
            return d
        d = os.path.dirname(d)
    raise RuntimeError("could not find repo root above " + start)


def lua_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def field_key(name):
    """Lua table constructor key: bare identifier where possible, otherwise
    a bracketed string literal."""
    if re.match(r"^[A-Za-z_]\w*$", name) and name not in LUA_RESERVED:
        return name
    return f"[{lua_str(name)}]"

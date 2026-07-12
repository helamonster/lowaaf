"""
Shared helpers for the MediaWiki WAF extraction/generation pipeline.

Every extract_*.py / gen_*.py / verify_*.py script in this directory (plus
notes/apps/mediawiki/extract_mediawiki_api.py) imports from here instead of
redefining these - they used to be copy-pasted verbatim across 5-6 different
files, confirmed identical byte-for-byte before consolidating.
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
    directory, rather than assuming a fixed relative depth - survives future
    reorganizations (this replaced a fixed-depth dirname() chain that broke
    when scripts moved from a flat layout into notes/apps/mediawiki/)."""
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
    a bracketed string literal (e.g. names with a '[]' suffix or containing
    characters that aren't valid in a plain Lua identifier)."""
    if re.match(r"^[A-Za-z_]\w*$", name) and name not in LUA_RESERVED:
        return name
    return f"[{lua_str(name)}]"

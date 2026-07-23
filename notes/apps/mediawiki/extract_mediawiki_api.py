#!/usr/bin/env python3
"""
extract_mediawiki_api.py

Walks a MediaWiki core source tree and extracts a structured, machine-readable
summary of every default API module's parameters (from getAllowedParams())
and every default Special: page's candidate request fields (heuristic), so
the mediawiki.lua WAF policy can be built/reviewed against real source
instead of guessed from traffic captures.

Usage:
    python3 extract_mediawiki_api.py [path-to-mediawiki-source] [output-dir]

Defaults:
    path-to-mediawiki-source = app-sources/mediawiki/server/mediawiki-<latest>
    output-dir               = ./mw-api-extract

Outputs (in output-dir):
    api-params.json       - structured: {module_key: {kind, class, file, prefix, params:{...}}}
    special-fields.json   - heuristic: {PageName: {class, file, candidate_fields:[...]}}
    extract.log           - notes on anything that couldn't be statically resolved
"""
import sys
import os
import re
import glob
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "mw-api-extract"))
from _lib import find_repo_root  # noqa: E402

# Well-known numeric constants referenced in PARAM_MIN/MAX/MAX2 instead of
# literal numbers (see includes/Api/ApiBase.php).
KNOWN_CONSTS = {
    "ApiBase::LIMIT_BIG1": 500,
    "ApiBase::LIMIT_BIG2": 5000,
    "ApiBase::LIMIT_SML1": 50,
    "ApiBase::LIMIT_SML2": 500,
}

# A handful of query-submodule classes serve several module keys and choose
# their wire-parameter prefix at runtime via a switch/lookup table keyed on
# $moduleName, rather than a literal 3rd constructor argument (e.g.
# ApiQueryLinks serves both "links" -> 'pl' and "templates" -> 'tl'). Those
# aren't worth generalizing a parser for, so they're hand-verified against
# the 1.46.0 source and listed here directly.
PREFIX_OVERRIDES = {
    "links": "pl", "templates": "tl",
    "backlinks": "bl", "embeddedin": "ei", "imageusage": "iu",
    "alllinks": "al", "alltransclusions": "at", "allfileusages": "af", "allredirects": "ar",
    "imageinfo": "ii",
    "redirects": "rd", "linkshere": "lh", "transcludedin": "ti", "fileusage": "fu",
    "tokens": "", "codexicons": "",
}


# ---------------------------------------------------------------------------
# PHP array-literal tokenizer/parser
# ---------------------------------------------------------------------------

class Tok:
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.n = len(text)

    def skip_ws_comments(self):
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif c == "/" and self.s[self.i:self.i + 2] == "//":
                j = self.s.find("\n", self.i)
                self.i = self.n if j == -1 else j + 1
            elif c == "#":
                j = self.s.find("\n", self.i)
                self.i = self.n if j == -1 else j + 1
            elif c == "/" and self.s[self.i:self.i + 2] == "/*":
                j = self.s.find("*/", self.i + 2)
                self.i = self.n if j == -1 else j + 2
            else:
                break

    def peek(self):
        return self.s[self.i] if self.i < self.n else ""

    def read_string(self):
        quote = self.s[self.i]
        j = self.i + 1
        buf = []
        while j < self.n:
            c = self.s[j]
            if c == "\\" and j + 1 < self.n:
                buf.append(self.s[j:j + 2])
                j += 2
                continue
            if c == quote:
                j += 1
                break
            buf.append(c)
            j += 1
        self.i = j
        raw = "".join(buf)
        if quote == "'":
            raw = raw.replace("\\'", "'").replace("\\\\", "\\")
        return raw

    def parse_value(self):
        self.skip_ws_comments()
        if self.i >= self.n:
            return None
        c = self.peek()
        if c in "'\"":
            return self.read_string()
        if c in "[(":
            return self.parse_array()
        # bareword: could be true/false/null, a number, a ::class/const ref,
        # a function/method call, or a bare identifier. Capture up to the
        # next top-level comma, "=>", or closing bracket at depth 0.
        return self.read_expr_until_delim()

    def read_expr_until_delim(self):
        start = self.i
        depth = 0
        j = self.i
        while j < self.n:
            c = self.s[j]
            if c in "([":
                depth += 1
            elif c in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                break
            elif c == "=" and depth == 0 and self.s[j:j + 2] == "=>":
                break
            elif c in "'\"":
                # skip over nested string so its commas/brackets don't confuse us
                q = c
                j += 1
                while j < self.n and self.s[j] != q:
                    if self.s[j] == "\\":
                        j += 1
                    j += 1
            j += 1
        text = self.s[start:j].strip()
        self.i = j
        return ("__expr__", text)

    def parse_array(self):
        open_c = self.s[self.i]
        close_c = "]" if open_c == "[" else ")"
        self.i += 1
        items = []
        pairs = {}
        is_list = True
        while True:
            self.skip_ws_comments()
            if self.i >= self.n:
                break
            if self.peek() == close_c:
                self.i += 1
                break
            key = self.parse_value()
            self.skip_ws_comments()
            if self.s[self.i:self.i + 2] == "=>":
                self.i += 2
                self.skip_ws_comments()
                val = self.parse_value()
                if isinstance(key, str):
                    keystr = key
                elif isinstance(key, tuple) and key[0] == "__expr__":
                    keystr = "__DYNAMIC_KEY__:" + key[1]
                else:
                    keystr = str(key)
                pairs[keystr] = val
                is_list = False
            else:
                items.append(key)
            self.skip_ws_comments()
            if self.peek() == ",":
                self.i += 1
                continue
            self.skip_ws_comments()
            if self.peek() == close_c:
                self.i += 1
                break
        return pairs if not is_list else items


def parse_one_array(text, pos):
    """Parse the array literal starting at text[pos] (a '[' or '('), return (value, end_pos)."""
    tok = Tok(text)
    tok.i = pos
    val = tok.parse_value()
    return val, tok.i


def const_tail(name):
    # 'ParamValidator::PARAM_TYPE' -> 'PARAM_TYPE', '\Foo\Bar::PARAM_X' -> 'PARAM_X'
    return name.rsplit("::", 1)[-1] if "::" in name else name


def resolve_scalar(v):
    if v is None:
        return None
    if isinstance(v, tuple) and v[0] == "__expr__":
        e = v[1]
        if e == "true":
            return True
        if e == "false":
            return False
        if e == "null":
            return None
        if re.fullmatch(r"-?\d+", e):
            return int(e)
        if e in KNOWN_CONSTS:
            return KNOWN_CONSTS[e]
        return {"__dynamic__": e}
    return v


def interpret_param(name, raw, module_key, log):
    # Shorthand: bare scalar (not an array/dict) => that's PARAM_DEFAULT, type inferred.
    if raw is None:
        return {"type": "string"}
    if isinstance(raw, tuple) and raw[0] == "__expr__":
        r = resolve_scalar(raw)
        if isinstance(r, bool):
            return {"type": "boolean", "default": r}
        if isinstance(r, int):
            return {"type": "integer", "default": r}
        if isinstance(r, dict) and "__dynamic__" in r:
            log.append(f"{module_key}.{name}: dynamic default {r['__dynamic__']!r}, type left generic")
            return {"type": "string"}
        return {"type": "string"}
    if isinstance(raw, str):
        return {"type": "string", "default": raw}
    if isinstance(raw, list):
        vals = [x for x in raw if isinstance(x, str)]
        if vals:
            return {"type": "enum", "enum": vals}
        return {"type": "string"}
    if isinstance(raw, dict):
        out = {"type": "string"}
        for k, v in raw.items():
            kk = const_tail(k)
            if kk == "PARAM_TYPE":
                if isinstance(v, str):
                    out["type"] = v
                elif isinstance(v, list):
                    vals = [x for x in v if isinstance(x, str)]
                    if vals and len(vals) == len(v):
                        out["type"] = "enum"
                        out["enum"] = vals
                    else:
                        log.append(f"{module_key}.{name}: PARAM_TYPE array not fully static, "
                                   f"treating as enum-of-strings with dynamic entries left out")
                        if vals:
                            out["type"] = "enum"
                            out["enum"] = vals
                elif isinstance(v, tuple) and v[0] == "__expr__":
                    log.append(f"{module_key}.{name}: PARAM_TYPE is dynamic ({v[1]!r}); left as generic string")
                    out["type"] = "string"
                    out["dynamic_type_expr"] = v[1]
            elif kk == "PARAM_REQUIRED":
                r = resolve_scalar(v)
                out["required"] = bool(r) if isinstance(r, bool) else False
            elif kk == "PARAM_ISMULTI":
                r = resolve_scalar(v)
                out["ismulti"] = bool(r) if isinstance(r, bool) else False
            elif kk == "PARAM_DEFAULT":
                out["default"] = resolve_scalar(v)
            elif kk in ("PARAM_MIN", "PARAM_MAX", "PARAM_MAX2"):
                r = resolve_scalar(v)
                if isinstance(r, int):
                    out[kk.lower()] = r
                elif isinstance(r, dict) and "__dynamic__" in r:
                    log.append(f"{module_key}.{name}: {kk} is dynamic/unresolved constant {r['__dynamic__']!r}")
            elif kk == "PARAM_DEPRECATED":
                out["deprecated"] = True
        return out
    return {"type": "string"}


def find_last_top_level_return(body_text):
    """Finds the method's own "return ...;" statement - specifically the LAST
    occurrence of the "return" keyword that sits at bracket depth 0 (i.e. not
    nested inside any (), [], or {} - which rules out "return" statements
    inside closures passed as array values, a common HTMLForm pattern like
    'validation-callback' => function ($v) { ... return true; }).

    A naive "return\\s+(.*?);\\s*}\\s*$" regex breaks here: re.search commits
    to the FIRST "return" it finds (even one inside a nested closure) as the
    match start, and the non-greedy group still has to expand across the
    entire rest of the method to reach the required end-of-string anchor,
    silently swallowing everything in between.

    Returns (start_pos, end_pos_of_statement_semicolon) for the expression
    between "return" and its terminating top-level ";", or None.
    """
    # body_text starts at "function name(...) {" - skip past that so
    # depth==0 below means "directly in the method body", not "one level
    # inside the method's own enclosing brace" (which would make depth==0
    # never occur for anything, since that brace is never closed until the
    # very last character of body_text).
    paren_depth = 0
    i = 0
    n = len(body_text)
    for i in range(n):
        ch = body_text[i]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth -= 1
        elif ch == "{" and paren_depth == 0:
            i += 1
            break

    depth = 0
    candidates = []  # (return_keyword_end, statement_end_exclusive_of_semicolon)
    while i < n:
        c = body_text[i]
        if c == "/" and body_text[i:i + 2] == "//":
            j = body_text.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if c == "/" and body_text[i:i + 2] == "/*":
            j = body_text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c in "'\"":
            quote = c
            i += 1
            while i < n and body_text[i] != quote:
                if body_text[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c in "([{":
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 0 and body_text[i:i + 6] == "return" and (i + 6 == n or not (body_text[i + 6].isalnum() or body_text[i + 6] == "_")):
            stmt_start = i + 6
            # Now scan forward (still respecting nested brackets/strings) to
            # find this statement's own terminating top-level ";".
            j = stmt_start
            local_depth = 0
            while j < n:
                cj = body_text[j]
                if cj == "/" and body_text[j:j + 2] == "//":
                    j = body_text.find("\n", j)
                    if j == -1:
                        j = n
                    continue
                if cj in "'\"":
                    q = cj
                    j += 1
                    while j < n and body_text[j] != q:
                        if body_text[j] == "\\":
                            j += 1
                        j += 1
                    j += 1
                    continue
                if cj in "([{":
                    local_depth += 1
                elif cj in ")]}":
                    local_depth -= 1
                elif cj == ";" and local_depth == 0:
                    break
                j += 1
            candidates.append((stmt_start, j))
            i = j + 1
            continue
        i += 1

    if not candidates:
        return None
    return candidates[-1]


def parse_return_array(body_text, module_key, log):
    # Strategy: first figure out which single variable is actually the one
    # getAllowedParams() returns (from its "return ..." statement), then only
    # look at assignments/merges into THAT variable. Without this scoping,
    # any unrelated local variable elsewhere in the method that happens to be
    # assigned an array literal (e.g. a throwaway "$p = [...]" inside a
    # foreach loop copying/rewriting a couple of fields) gets misread as part
    # of the top-level params dict.
    merged = {}
    found_any = False
    consumed = []

    def overlaps(pos):
        return any(s <= pos < e for s, e in consumed)

    def merge_literal_at(pos):
        nonlocal found_any
        if overlaps(pos):
            return
        val, end = parse_one_array(body_text, pos)
        if isinstance(val, dict):
            merged.update(val)
            found_any = True
            consumed.append((pos, end))

    ret_span = find_last_top_level_return(body_text)
    if not ret_span:
        return None
    ret_start, ret_end = ret_span
    ret_expr_raw = body_text[ret_start:ret_end]
    ret_expr = ret_expr_raw.strip()
    # absolute offset of ret_expr within body_text, accounting for leading
    # whitespace stripped by .strip()
    ret_expr_abs_start = ret_start + (len(ret_expr_raw) - len(ret_expr_raw.lstrip()))

    varname = None
    m = re.match(r"\$(\w+)\s*\+?", ret_expr)
    if m:
        varname = m.group(1)

    # "return [...]" or "return X + [...]" (literal directly in the return
    # statement, whether or not X is also a variable handled below).
    lit_m = re.search(r"(\[|array\()", ret_expr)
    if lit_m:
        merge_literal_at(ret_expr_abs_start + lit_m.start())

    if varname:
        # 1) Indexed single-key assignment into the return variable:
        #    "$allowedParams['sort'] = [...]" - one parameter's definition,
        #    must be merged as merged[key] = value, not spread.
        for m in re.finditer(r"\$" + re.escape(varname) + r"\[\s*['\"](\w+)['\"]\s*\]\s*=\s*(\[|array\()", body_text):
            key = m.group(1)
            pos = m.start(2)
            if overlaps(pos):
                continue
            val, end = parse_one_array(body_text, pos)
            merged[key] = val if isinstance(val, dict) else {"type": "string"}
            found_any = True
            consumed.append((pos, end))

        # 2) Direct/merge assignment of the whole dict:
        #    "$var = [...]", "$var = X + [...]", "$var += [...]"
        for m in re.finditer(
            r"\$" + re.escape(varname) + r"\s*(\+=|=)\s*([\w:>\$\-\(\)\s,]*\s*\+\s*)?(\[|array\()", body_text
        ):
            merge_literal_at(m.start(3))

        # 3) Indexed assignment with a non-literal (variable) index, e.g.
        #    "$ret[$to] = $p;" inside a foreach - can't resolve statically.
        for m in re.finditer(r"\$" + re.escape(varname) + r"\[\s*\$\w+\s*\]\s*=", body_text):
            log.append(f"{module_key}: getAllowedParams() assigns '{m.group(0)}' with a "
                       f"non-literal (variable) key, NOT captured here")

    # Note (but don't fail on) call-based pieces we can't resolve statically.
    for m in re.finditer(r"(parent::getAllowedParams\(\)|\$this->[A-Za-z_]+\([^()]*\))", body_text):
        pos = m.start()
        if overlaps(pos):
            continue
        log.append(f"{module_key}: getAllowedParams() includes '{m.group(1)}' - "
                   f"a parent/helper call, not statically resolved, NOT captured here")

    if found_any:
        return merged
    return None


# ---------------------------------------------------------------------------
# Parent-class resolution (for "parent::getAllowedParams()" calls)
# ---------------------------------------------------------------------------

_parent_cache = {}


def find_class_file_by_name(cls, search_dir):
    hits = glob.glob(os.path.join(search_dir, f"{cls}.php"))
    if hits:
        return hits[0]
    for path in glob.glob(os.path.join(search_dir, "*.php")):
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(2000)
        if re.search(r"^class\s+" + re.escape(cls) + r"\b", head, re.M):
            return path
    return None


def extract_method_body(src, method_name):
    """Extract a tab-indented PHP method body: from the signature line to the
    first line that is exactly one tab followed by a closing brace."""
    m = re.search(r"function " + re.escape(method_name) + r".*?\n\t\}\n", src, re.S)
    return m.group(0) if m else None


def resolve_parent_params(cls, search_dir, log, depth=0, max_depth=2):
    if depth > max_depth or cls in _parent_cache:
        return _parent_cache.get(cls, {})
    _parent_cache[cls] = {}  # guard against cycles during recursion

    path = find_class_file_by_name(cls, search_dir)
    if not path:
        return {}
    src = open(path, encoding="utf-8", errors="replace").read()

    m = re.search(r"class\s+" + re.escape(cls) + r"\s+extends\s+(\w+)", src)
    base_fields = {}
    if m and depth < max_depth:
        base_fields = resolve_parent_params(m.group(1), search_dir, log, depth + 1, max_depth)

    own_fields = {}
    body = extract_method_body(src, "getAllowedParams")
    if body:
        try:
            arr = parse_return_array(body, f"{cls}(parent)", log)
        except Exception:
            arr = None
        if isinstance(arr, dict):
            for pname, praw in arr.items():
                if isinstance(pname, str) and not pname.startswith("__DYNAMIC_KEY__:"):
                    own_fields[pname] = interpret_param(pname, praw, f"{cls}(parent)", log)

    result = {**base_fields, **own_fields}
    _parent_cache[cls] = result
    return result


def check_needs_token(cls, src, api_dir, log, depth=0, max_depth=3):
    """ApiBase::getFinalParams() silently injects a required 'token' param
    for any module whose needsToken() returns a truthy token-type string -
    even when the module's own getAllowedParams() never mentions 'token'
    (e.g. ApiStashEdit, ApiBlock, ApiDelete, ApiMove all rely purely on this
    implicit mechanism). getAllowedParams()-only extraction misses these
    entirely, so this has to be checked separately."""
    body = extract_method_body(src, "needsToken")
    if body is not None:
        returns = re.findall(r"return\s+([^;]+);", body)
        if not returns:
            return False
        # A literal `return false;` with no other return statement in the
        # method means this module truly never needs a token. Anything else
        # (a literal token-type string, or a conditional mix of `false` and
        # a string) means a token is possible - stay permissive and allow it,
        # since the field is always modeled as optional anyway.
        if len(returns) == 1 and returns[0].strip() == "false":
            return False
        return True

    if depth >= max_depth:
        return False
    m = re.search(r"class\s+" + re.escape(cls) + r"\s+extends\s+(\w+)", src)
    if not m:
        return False
    parent_file = find_class_file_by_name(m.group(1), api_dir)
    if not parent_file:
        return False
    parent_src = open(parent_file, encoding="utf-8", errors="replace").read()
    return check_needs_token(m.group(1), parent_src, api_dir, log, depth + 1, max_depth)


# ---------------------------------------------------------------------------
# Module registration discovery
# ---------------------------------------------------------------------------

def extract_registrations(file_path, const_name):
    """Extract 'modulekey' => ['class' => ApiWhatever::class, ...] pairs from
    a `private const CONST_NAME = [...]` block. Returns [(key, class), ...].
    Deliberately scoped to just the class name (not any 'services' => [...]
    sub-array also present in each block, which would desync a naive
    alternating-match approach)."""
    src = open(file_path, encoding="utf-8", errors="replace").read()
    m = re.search(r"private const " + re.escape(const_name) + r" = \[(.*?)\n\t\];", src, re.S)
    if not m:
        return []
    block = m.group(1)
    return [(mm.group(1), mm.group(2))
            for mm in re.finditer(r"'(\w+)'\s*=>\s*\[\s*'class'\s*=>\s*([\w\\]+)::class", block)]


def find_class_file(cls, api_dir):
    for path in glob.glob(os.path.join(api_dir, "*.php")):
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(2000)
        if re.search(r"^class\s+" + re.escape(cls) + r"\b", head, re.M):
            return path
    guess = os.path.join(api_dir, f"{cls}.php")
    return guess if os.path.isfile(guess) else None


def find_module_prefix(cls, key, kind, file_path, log):
    """Returns (prefix, verified). Action modules aren't prefixed at all."""
    if kind == "action":
        return "", False
    if key in PREFIX_OVERRIDES:
        return PREFIX_OVERRIDES[key], True
    src = open(file_path, encoding="utf-8", errors="replace").read()
    m = re.search(r"parent::__construct\s*\(\s*\$\w+,\s*\$moduleName,\s*'([a-z]+)'", src)
    if m:
        return m.group(1), False
    return "", False


# ---------------------------------------------------------------------------
# Main API-module extraction
# ---------------------------------------------------------------------------

def extract_api_modules(mw_src, api_dir, log):
    api_main = os.path.join(api_dir, "ApiMain.php")
    api_query = os.path.join(api_dir, "ApiQuery.php")

    registrations = []  # (key, class, kind)
    for key, cls in extract_registrations(api_main, "MODULES"):
        registrations.append((key, cls, "action"))
    for kind, const in (("prop", "QUERY_PROP_MODULES"), ("list", "QUERY_LIST_MODULES"), ("meta", "QUERY_META_MODULES")):
        for key, cls in extract_registrations(api_query, const):
            registrations.append((key, cls, kind))

    print(f"Found {len(registrations)} module registrations.")

    modules = {}
    for key, cls, kind in registrations:
        file_path = find_class_file(cls, api_dir)
        if not file_path:
            print(f"WARN: could not locate source file for class {cls} (module '{key}')", file=sys.stderr)
            continue
        rel_file = os.path.relpath(file_path, mw_src)

        prefix, prefix_verified = find_module_prefix(cls, key, kind, file_path, log)
        if kind != "action" and not prefix and not prefix_verified:
            log.append(f"{key} ({cls}): no module prefix found via parent::__construct() - "
                       f"parameter names below are UNPREFIXED and likely do not match the real wire format")

        entry = {"kind": kind, "class": cls, "file": rel_file, "prefix": prefix, "params": {}}

        src = open(file_path, encoding="utf-8", errors="replace").read()
        body = extract_method_body(src, "getAllowedParams")
        if not body:
            log.append(f"{key} ({cls}): no getAllowedParams() found (likely takes no params)")
        else:
            try:
                arr = parse_return_array(body, key, log)
            except Exception as e:
                log.append(f"{key} ({cls}): FAILED to parse getAllowedParams() body: {e}")
                arr = None

            if not isinstance(arr, dict):
                log.append(f"{key} ({cls}): getAllowedParams() did not resolve to a static array (dynamic construction)")
            else:
                def wire_name(pname):
                    return (prefix + pname) if (kind != "action" and prefix) else pname

                # Resolve "parent::getAllowedParams()" by walking up the class's
                # own `extends` chain and merging its fields in first (child
                # overrides).
                if "parent::getAllowedParams()" in body:
                    cm = re.search(r"class\s+" + re.escape(cls) + r"\s+extends\s+(\w+)", src)
                    if cm:
                        raw_parent_fields = resolve_parent_params(cm.group(1), api_dir, log)
                        for pname, spec in raw_parent_fields.items():
                            entry["params"][wire_name(pname)] = spec
                        if not raw_parent_fields:
                            log.append(f"{key} ({cls}): could not resolve parent class {cm.group(1)}'s "
                                       f"getAllowedParams() either - parent fields NOT captured here")

                for pname, praw in arr.items():
                    if pname.startswith("__DYNAMIC_KEY__:"):
                        log.append(f"{key}: getAllowedParams() has a parameter with a computed (non-literal) "
                                   f"name from {pname[len('__DYNAMIC_KEY__:'):]!r}, NOT captured here")
                        continue
                    entry["params"][wire_name(pname)] = interpret_param(pname, praw, key, log)

        # SearchApi::buildCommonApiParams() (search/namespace/limit/offset) is
        # a shared trait method, not a static array - getAllowedParams() for
        # its 3 users (ApiQuerySearch, ApiQueryPrefixSearch, ApiOpenSearch -
        # the last an action=, unprefixed, hence no `and kind != "action"`
        # exclusion here) just calls it directly
        # (`return $this->buildCommonApiParams();`) or merges it in via `+`,
        # so parse_return_array() can't see these fields at all (silently,
        # for the `+`-merge case - no log entry). Confirmed empty in the
        # wild: list=search's own srsearch and list=prefixsearch's pssearch -
        # i.e. the actual search query itself - were both missing before this.
        if "use SearchApi" in src:
            search_api_fields = {
                "search": {"type": "string", "required": True},
                "namespace": {"type": "namespace"},
                "limit": {"type": "limit"},
                "offset": {"type": "integer"},
            }
            for pname, spec in search_api_fields.items():
                wname = (prefix + pname) if prefix else pname
                entry["params"].setdefault(wname, spec)

        # ApiBase::getFinalParams() injects an implicit 'token' param for any
        # module whose needsToken() is truthy, regardless of what
        # getAllowedParams() itself declares - action modules only (query
        # prop/list/meta submodules are read-only and never override it).
        if kind == "action" and "token" not in entry["params"] and check_needs_token(cls, src, api_dir, log):
            entry["params"]["token"] = {
                "type": "string",
                "note": "sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()",
            }

        modules[key] = entry

    return modules


# ---------------------------------------------------------------------------
# Special: pages heuristic scan
# ---------------------------------------------------------------------------

# HTMLForm 'type' values -> our validator type vocabulary. Used for fields
# discovered via a FormSpecialPage subclass's getFormFields().
HTMLFORM_TYPE_MAP = {
    "text": "string", "textarea": "string", "title": "string", "url": "string",
    "email": "string", "hidden": "string", "combobox": "string", "date": "string",
    "namespaceselect": "string", "usersmultiselect": "string", "titlesmultselect": "string",
    "cloner": "string", "selectorother": "string", "submit": "string",
    "user": "user", "password": "password",
    "int": "integer", "float": "integer",
    "check": "boolean", "toggle": "boolean",
    "select": "enum", "radio": "enum", "multiselect": "enum",
}


def find_class_file_in_dir(cls, search_dir):
    for root, _, files in os.walk(search_dir):
        if f"{cls}.php" in files:
            return os.path.join(root, f"{cls}.php")
    return None


def interpret_htmlform_field(name, raw, log, page_key):
    """Mirrors interpret_param() but for HTMLForm field descriptors, which use
    a different key vocabulary ('type'/'required'/'options'/'default'/'name')
    than ParamValidator's PARAM_* constants."""
    if not isinstance(raw, dict):
        return "wp" + name, {"type": "string"}

    wire_name = raw.get("name")
    if not isinstance(wire_name, str):
        wire_name = "wp" + name

    out = {"type": "string"}
    t = raw.get("type")
    if isinstance(t, str) and t in HTMLFORM_TYPE_MAP:
        out["type"] = HTMLFORM_TYPE_MAP[t]
    elif isinstance(t, str):
        log.append(f"{page_key}.{wire_name}: unrecognized HTMLForm type {t!r}, left as generic string")

    if out["type"] == "enum":
        opts = raw.get("options") or raw.get("options-messages") or raw.get("options-messages-parse")
        vals = None
        if isinstance(opts, dict):
            vals = [v for v in opts.values() if isinstance(v, str)]
        if vals:
            out["enum"] = vals
        else:
            log.append(f"{page_key}.{wire_name}: HTMLForm 'select'/'radio' options not statically "
                       f"resolved, left as generic string")
            out["type"] = "string"

    req = raw.get("required")
    if isinstance(req, bool):
        out["required"] = req

    return wire_name, out


def extract_form_fields(file_path, page_key, log):
    """Parses a FormSpecialPage subclass's getFormFields() (or the closely
    related getFields()/getLegend() pattern some pages use) the same way
    ApiBase::getAllowedParams() is parsed - it's the same PHP array-literal
    shape ($a['FieldName'] = [...]; return $a;)."""
    src = open(file_path, encoding="utf-8", errors="replace").read()
    body = extract_method_body(src, "getFormFields")
    if not body:
        return None
    try:
        arr = parse_return_array(body, page_key, log)
    except Exception as e:
        log.append(f"{page_key}: FAILED to parse getFormFields() body: {e}")
        return None
    if not isinstance(arr, dict):
        return None

    fields = {}
    for fname, fraw in arr.items():
        if fname.startswith("__DYNAMIC_KEY__:"):
            log.append(f"{page_key}: getFormFields() has a computed (non-literal) field name from "
                       f"{fname[len('__DYNAMIC_KEY__:'):]!r}, NOT captured here")
            continue
        wire_name, spec = interpret_htmlform_field(fname, fraw, log, page_key)
        fields[wire_name] = spec
    return fields


def extract_redirect_passthrough(file_path, cls, log):
    """SpecialRedirectToSpecial / SpecialRedirectWithAction / RedirectSpecialPage
    subclasses just forward to another page, passing through a short list of
    query params given as an array literal argument to their parent::__construct()
    call (e.g. SpecialChangePassword -> Special:ChangeCredentials, passing
    through ['returnto', 'returntoquery'])."""
    src = open(file_path, encoding="utf-8", errors="replace").read()
    m = re.search(r"class\s+" + re.escape(cls) + r"\s+extends\s+(\w+)", src)
    if not m or "Redirect" not in m.group(1):
        return None
    ctor = re.search(r"parent::__construct\s*\((.*?)\);", src, re.S)
    if not ctor:
        return None
    arr_m = re.search(r"(\[|array\()", ctor.group(1))
    if not arr_m:
        return {}
    val, _ = parse_one_array(ctor.group(1), arr_m.start())
    if isinstance(val, list):
        return {v: {"type": "string"} for v in val if isinstance(v, str)}
    return {}


_QUERY_PAGE_BASES = {
    "QueryPage", "PageQueryPage", "ImageQueryPage", "WantedQueryPage",
    "SpecialUncategorizedPages", "SpecialRandomPage", "SpecialFewestRevisions",
    "SpecialShortPages",
}

# Shared by extract_special_pages() and extract_editpage_fields(): a generic
# heuristic scan of $request->getXxx('name') calls. Includes the file-upload
# accessors (getFileName/getUpload/...) since a missed one of those is exactly
# what caused Special:Upload's wpUploadFile to be silently dropped. The
# charset includes '-' - MediaWiki field names like 'mwProtect-reason' and
# 'mwProtect-level-create' use hyphens, and excluding them from the class
# silently drops the whole match rather than truncating it (cost us
# mwProtect-reason/mwProtect-cascade the first time around).
#
# The method name is its own capture group (not lumped into one non-
# capturing alternation) so extract_field_calls() below can tell getArray()/
# getArrayOrNull() calls apart from the rest: those read a classic PHP
# array-parameter, whose real WIRE name has a "[]" suffix the PHP-side
# string literal never includes (e.g. SpecialProtectedPages.php calls
# $request->getArray('wpfilters', []) but the real submitted param is
# wpfilters[] - confirmed live: a real ProtectedPages filter-UI request got
# denied because the extracted field name was missing the brackets).
FIELD_CALL_RE = re.compile(
    r"->get(Val|Text|Int|Bool|Check|IntOrNull|RawVal|Array|ArrayOrNull"
    r"|FileName|Upload|FileTempname|UploadError)\(\s*['\"]([A-Za-z0-9_\-\[\]]+)['\"]"
)

ARRAY_GETTER_METHODS = {"Array", "ArrayOrNull"}


def extract_field_calls(src_text):
    """Runs FIELD_CALL_RE over src_text and returns the set of real WIRE
    field names - appending "[]" for getArray()/getArrayOrNull() calls
    whose PHP-side string argument never includes it."""
    names = set()
    for method, name in FIELD_CALL_RE.findall(src_text):
        if method in ARRAY_GETTER_METHODS and not name.endswith("[]"):
            name = name + "[]"
        names.add(name)
    return names


def resolve_class_const_key(dynamic_key, search_dir):
    """Resolves a '__DYNAMIC_KEY__:ClassName::CONST_NAME' array key (as
    produced by Tok.parse_array() for a non-literal key expression) back to
    its string value, by finding ClassName's file under search_dir and
    reading its own `const CONST_NAME = '...'` declaration. Used for skin
    hooks like Vector's `Constants::PREF_KEY_LIMITED_WIDTH => [...]`, which
    ParamValidator-style parsing alone can't see through."""
    if not dynamic_key.startswith("__DYNAMIC_KEY__:"):
        return None
    expr = dynamic_key[len("__DYNAMIC_KEY__:"):].strip()
    m = re.match(r"^(\w+)::(\w+)$", expr)
    if not m:
        return None
    cls, const = m.groups()
    path = find_class_file_in_dir(cls, search_dir)
    if not path:
        return None
    src = open(path, encoding="utf-8", errors="replace").read()
    cm = re.search(r"const\s+" + re.escape(const) + r"\s*=\s*['\"]([^'\"]*)['\"]", src)
    return cm.group(1) if cm else None


# DefaultPreferencesFactory::getFormDescriptor() doesn't return one array
# literal (extract_form_fields()'s assumption) - it builds $defaultPreferences
# incrementally via `$defaultPreferences['key'] = [...]` assignments scattered
# across ~15 separate methods (profilePreferences(), skinPreferences(), ...).
# That mismatch is exactly why a plain getFormFields()-style scan found
# nothing for Special:Preferences.
PREF_ASSIGN_RE = re.compile(r"\$defaultPreferences\[\s*'([\w\-]+)'\s*\]\s*=\s*(?=\[)")


# $defaultPreferences[$pref] = [...] (watchlist toggles) and
# $defaultPreferences["$pref-expiry"] = [...] loop over a small, statically
# enumerable $watchTypes value set that a regex scan can't trace through -
# read directly from the source around the `$watchTypes = [...]` / `+=` block
# in DefaultPreferencesFactory.php (search "watchTypes" there to re-verify
# against a future MediaWiki version). All are boolean toggles; only
# edit/read/rollback's get the paired "-expiry" select field.
WATCH_TYPE_PREFS = ["watchdefault", "watchmoves", "watchcreations", "watchrollback", "watchuploads", "watchdeletion"]
WATCH_TYPE_PREFS_WITH_EXPIRY = ["watchdefault", "watchcreations", "watchrollback"]

# Html::hidden('wpServerTime', ...) - a raw hidden HTML input, not part of the
# $defaultPreferences[...] HTMLForm-descriptor pattern the rest of this
# function scans for.
PREFERENCES_EXTRA_FIELDS = {"wpServerTime": {"type": "string"}}


def extract_preferences_fields(mw_src, log):
    path = os.path.join(mw_src, "includes", "Preferences", "DefaultPreferencesFactory.php")
    if not os.path.isfile(path):
        log.append(f"Preferences: expected file not found at {path}")
        return {}
    src = open(path, encoding="utf-8", errors="replace").read()

    fields = {}
    for m in PREF_ASSIGN_RE.finditer(src):
        key = m.group(1)
        try:
            raw, _ = parse_one_array(src, m.end())
        except Exception as e:
            log.append(f"Preferences.{key}: FAILED to parse descriptor array: {e}")
            continue
        wire_name, spec = interpret_htmlform_field(key, raw, log, "Preferences")
        fields[wire_name] = spec

    for pref in WATCH_TYPE_PREFS:
        fields.setdefault("wp" + pref, {"type": "boolean"})
    for pref in WATCH_TYPE_PREFS_WITH_EXPIRY:
        fields.setdefault(f"wp{pref}-expiry", {"type": "string"})
    for name, spec in PREFERENCES_EXTRA_FIELDS.items():
        fields.setdefault(name, spec)

    # Any other interpolated/loop-generated keys ("variant-$langCode", ...)
    # can't be resolved statically - note how many were skipped.
    n_total_assigns = len(re.findall(r"\$defaultPreferences\[\s*[$\"][^\]]*\]\s*=\s*\[", src))
    n_dynamic = n_total_assigns - len(PREF_ASSIGN_RE.findall(src))
    if n_dynamic > 0:
        log.append(f"Preferences: {n_dynamic} dynamically-keyed $defaultPreferences[...] "
                   f"assignments found beyond the hardcoded watch-type set "
                   f"(interpolated/loop-generated keys), not captured")

    return fields


# Bundled skins that hook additional preference fields via onGetPreferences()
# (GetPreferences hook) - MonoBook/Timeless don't register any.
_SKIN_HOOK_CLASSES = {"Vector": "Hooks", "MinervaNeue": "Hooks"}


def extract_skin_preferences_fields(mw_src, log):
    fields = {}
    skins_dir = os.path.join(mw_src, "skins")
    if not os.path.isdir(skins_dir):
        log.append(f"skin preferences: no skins/ directory found at {skins_dir}")
        return fields

    for skin, hook_cls in _SKIN_HOOK_CLASSES.items():
        skin_dir = os.path.join(skins_dir, skin)
        hook_path = find_class_file_in_dir(hook_cls, skin_dir)
        if not hook_path:
            log.append(f"{skin}: no {hook_cls}.php found under {skin_dir}")
            continue
        src = open(hook_path, encoding="utf-8", errors="replace").read()
        body = extract_method_body(src, "onGetPreferences")
        if not body:
            continue
        arr_m = re.search(r"=\s*(?=\[)", body)
        if not arr_m:
            continue
        try:
            raw, _ = parse_one_array(body, arr_m.end())
        except Exception as e:
            log.append(f"{skin}: FAILED to parse onGetPreferences() array: {e}")
            continue
        if not isinstance(raw, dict):
            continue
        for key, val in raw.items():
            resolved = resolve_class_const_key(key, skin_dir) if key.startswith("__DYNAMIC_KEY__:") else key
            if resolved is None:
                log.append(f"{skin}.{key}: could not resolve dynamic preference key, not captured")
                continue
            wire_name, spec = interpret_htmlform_field(resolved, val, log, skin)
            fields[wire_name] = spec

    return fields


# Generic framework base classes - stop the parent-class walk here rather
# than scanning them (no page-specific fields to find, just wasted work).
_GENERIC_SPECIALPAGE_BASES = {"SpecialPage", "FormSpecialPage", "UnlistedSpecialPage", "IncludableSpecialPage"}


def heuristic_scan_with_parents(hit, short, mw_src, max_depth=3):
    """Scans a page's own file, then walks up its `extends` chain (searching
    the whole includes/ tree, since parent base classes for Special: pages
    can live in a different subdirectory than the concrete page itself -
    e.g. SpecialCreateAccount.php sits in includes/Specials/ but ALL of its
    real form-building logic is in LoginSignupSpecialPage.php, over in
    includes/SpecialPage/). A page's own file is often a thin wrapper with
    nothing to find; without this walk, pages like CreateAccount silently
    resolve to almost no fields even though the heuristic scan itself is
    working fine - it's just looking in the wrong file."""
    includes_dir = os.path.join(mw_src, "includes")
    names = set()
    seen = set()
    cur_cls, cur_file = short, hit
    for _ in range(max_depth):
        if cur_cls in seen or cur_cls in _GENERIC_SPECIALPAGE_BASES:
            break
        seen.add(cur_cls)
        src_text = open(cur_file, encoding="utf-8", errors="replace").read()
        names |= extract_field_calls(src_text)
        names |= {n for n in WP_LITERAL_RE.findall(src_text) if not WP_LITERAL_EXCLUDE_RE.search(n)}
        m = re.search(r"class\s+" + re.escape(cur_cls) + r"\s+extends\s+(\w+)", src_text)
        if not m:
            break
        parent_cls = m.group(1)
        parent_file = find_class_file_in_dir(parent_cls, includes_dir)
        if not parent_file:
            break
        cur_cls, cur_file = parent_cls, parent_file
    return names


def extract_special_pages(special_factory_path, specials_dir, log):
    src = open(special_factory_path, encoding="utf-8", errors="replace").read()
    m = re.search(r"private const CORE_LIST = \[(.*?)\n\t\];", src, re.S)
    list_body = m.group(1) if m else ""

    entries = re.findall(r"'([A-Za-z0-9_]+)'\s*=>\s*\[\s*'class'\s*=>\s*([A-Za-z0-9_\\]+)::class", list_body)
    mw_src = os.path.dirname(os.path.dirname(specials_dir))

    result = {}
    for page, cls in entries:
        short = cls.rsplit("\\", 1)[-1]
        hit = find_class_file_in_dir(short, specials_dir)
        if not hit:
            result[page] = {"class": short, "file": None, "method": "not_found", "fields": {}}
            continue

        rel_file = os.path.relpath(hit, os.path.dirname(specials_dir))
        extends_m = re.search(r"class\s+" + re.escape(short) + r"\s+extends\s+(\w+)",
                               open(hit, encoding="utf-8", errors="replace").read())
        base = extends_m.group(1) if extends_m else None

        # 0) SpecialPreferences delegates to DefaultPreferencesFactory, which
        #    scatters $defaultPreferences['key'] = [...] assignments across
        #    ~15 methods instead of one getFormFields()-style return array -
        #    needs its own extraction, plus whatever the bundled skins hook in.
        if page == "Preferences":
            fields = extract_preferences_fields(mw_src, log)
            fields.update(extract_skin_preferences_fields(mw_src, log))
            result[page] = {"class": short, "file": rel_file, "extends": base,
                            "method": "form_fields", "fields": fields}
            continue

        # 1) FormSpecialPage-family: precise fields + types from getFormFields().
        form_fields = extract_form_fields(hit, page, log)
        if form_fields:
            result[page] = {"class": short, "file": rel_file, "extends": base,
                            "method": "form_fields", "fields": form_fields}
            continue

        # 1b) SpecialRedirectWithAction-family (EditPage, PageHistory,
        #     DeletePage, ProtectPage, PageInfo, Purge - confirmed via source
        #     read, includes/SpecialPage/SpecialRedirectWithAction.php):
        #     shows an HTMLForm with one hardcoded, always-identical field
        #     ('page', a title, required) built inline in the SHARED base
        #     class's own showForm(), then redirects to
        #     title=<page>&action=<X> on submit. Neither of our two
        #     heuristics can see it: FIELD_CALL_RE needs a
        #     $request->getXxx('name') call (this reads $formData['page'],
        #     plain array access, not a WebRequest getter), and WP_LITERAL_RE
        #     only matches 'wpXxx'-prefixed literals ('page' isn't prefixed -
        #     HTMLForm's own field descriptor gives it an explicit
        #     'name' => 'page' override, same mechanism that produced
        #     'wpusername' vs 'username' inconsistently elsewhere). Would
        #     otherwise fall through to method=redirect_passthrough with zero
        #     fields found - confirmed live: a real Special:ProtectPage
        #     submission got denied on exactly this field.
        if base == "SpecialRedirectWithAction":
            result[page] = {"class": short, "file": rel_file, "extends": base,
                            "method": "form_fields",
                            "fields": {"page": {"type": "string", "required": True}}}
            continue

        # 2) Redirect stubs: pass-through query params from the constructor call.
        redirect_fields = extract_redirect_passthrough(hit, short, log)
        if redirect_fields is not None:
            result[page] = {"class": short, "file": rel_file, "extends": base,
                            "method": "redirect_passthrough", "fields": redirect_fields}
            continue

        # 3) QueryPage-family report pages: standard pagination only, already
        #    covered by idx_common (limit/offset/dir/...) - no extra fields.
        if base in _QUERY_PAGE_BASES:
            result[page] = {"class": short, "file": rel_file, "extends": base,
                            "method": "query_page_standard", "fields": {}}
            continue

        # 4) Fallback: heuristic scan of direct $request->getXxx()/getBool()
        #    calls, PLUS bare 'wpXxx' field-name literals (HTMLForm/OOUI
        #    widget 'name' => 'wpFoo' configs, Html::hidden('wpFoo', ...)) -
        #    the same combination that turned up wpSave/wpWatchlistLabels for
        #    EditPage.php, which $request->getXxx() alone never sees since
        #    the page's own PHP never reads its own submit button back. Also
        #    walks up the extends chain (CreateAccount -> LoginSignupSpecialPage,
        #    DeletedContributions -> ContributionsSpecialPage, ...) since a
        #    page's own file is frequently a thin wrapper around shared logic.
        heuristic = sorted(heuristic_scan_with_parents(hit, short, mw_src))
        heuristic = [HEURISTIC_NAME_CORRECTIONS.get((page, n), n) for n in heuristic]
        heuristic = sorted(set(heuristic) | set(AUTHMANAGER_EXTRA_FIELDS.get(page, [])))
        result[page] = {
            "class": short, "file": rel_file, "extends": base,
            "method": "heuristic" if heuristic else "none",
            "fields": {name: {"type": "string"} for name in heuristic},
        }

    return result


# Bare 'wpXxx' string literals - catches form-field names declared via
# HTMLForm/OOUI widget config ('name' => 'wpSave') or Html::hidden('wpX', ...)
# that $request->getXxx() never reads back directly in PHP (the framework
# submits them, but EditPage.php itself has no reason to read its own submit
# button's name). Missing exactly this pattern is what dropped wpSave and
# wpWatchlistLabels - real submitted fields with no matching FIELD_CALL_RE hit.
# Excludes DOM-only wrapper ids (...Widget) and label ids (...Label, but not
# the genuine field wpWatchlistLabels, which ends in the plural "Labels").
WP_LITERAL_RE = re.compile(r"'(wp[A-Za-z0-9\-]+)'")
WP_LITERAL_EXCLUDE_RE = re.compile(r"(?:Widget|Label)$")

# WP_LITERAL_RE can't tell an HTMLForm field descriptor's 'id' => '...'
# (a cosmetic CSS/JS hook, camelCase by convention) apart from its 'name' =>
# '...' (the real submitted field, actually 'wp' + the descriptor's own
# ARRAY KEY, case preserved) - they're usually identical so this rarely
# matters, but LoginSignupSpecialPage.php's 'loginattempt' descriptor
# (includes/SpecialPage/LoginSignupSpecialPage.php:1176) has
# 'id' => 'wpLoginAttempt' while the actual submitted name, derived from the
# lowercase array key, is 'wploginattempt' - confirmed live: a real login
# POST got denied on exactly this field. Corrected by hand here rather than
# teaching the heuristic to parse full descriptor arrays (name= vs id= vs
# bare array key) for what is, so far, a single confirmed mismatch.
HEURISTIC_NAME_CORRECTIONS = {
    ("Userlogin", "wpLoginAttempt"): "wploginattempt",
    ("CreateAccount", "wpLoginAttempt"): "wploginattempt",
}

# ChangeCredentials/RemoveCredentials/LinkAccounts/UnlinkAccounts are built
# entirely by AuthManager from a set of AuthenticationRequest objects
# (includes/Auth/*AuthenticationRequest.php) that the page itself never
# mentions by field name - heuristic_scan_with_parents's extends-chain walk
# can't find them because these classes are COMPOSED/used, not inherited
# from. Worse, the same logical field gets a DIFFERENT wire name depending
# on which layer produces it: AuthManagerSpecialPage::mapSingleFieldInfo()
# explicitly does NOT prefix names sourced directly from
# AuthenticationRequest::getFieldInfo() ("Do not prefix input name with
# 'wp'. This is important for the redirect flow." - literally in a code
# comment there), but a Special page's OWN supplemental descriptor entries
# (added via onAuthChangeFormFields(), with no explicit 'name' override)
# fall through to HTMLForm's ordinary 'wp' + array-key default instead. No
# regex heuristic can reliably tell those two cases apart; hand-verified
# from source instead of guessed:
#   - PasswordAuthenticationRequest::getFieldInfo() for ACTION_CHANGE
#     (includes/Auth/PasswordAuthenticationRequest.php) returns 'password'
#     and 'retype', both unprefixed.
#   - SpecialChangeCredentials::onAuthChangeFormFields()
#     (includes/Specials/SpecialChangeCredentials.php) additionally injects
#     its own 'username' field (readonly, autofill-hint only, per T263927)
#     with no 'name' override, so it becomes 'wpusername' via HTMLForm's
#     default - confirmed live: a real credentials-change POST got denied
#     on password/retype/wpusername all at once.
#   - RemoveCredentials sets $loadUserData = false, so
#     getAuthFormDescriptor() returns [] unconditionally - nothing to add.
#   - LinkAccounts/UnlinkAccounts are gated on canLinkAccounts() (only
#     meaningful with an SSO/OAuth-style extension installed) and mostly use
#     ButtonAuthenticationRequest, whose field name is $this->name - set per
#     provider at runtime, not a fixed string in core - so there's nothing
#     reliable to hardcode here without knowing which extension is active.
#     A core-only install won't hit this; an install with such an extension
#     may see gaps here that this table can't cover.
AUTHMANAGER_EXTRA_FIELDS = {
    "ChangeCredentials": ["password", "retype", "wpusername"],
}


def extract_editpage_fields(mw_src, log):
    """The standard wikitext edit-submission form (EditPage.php) isn't a
    Special: page - it's driven by the Action system (action=edit/submit),
    so it falls outside extract_special_pages()'s CORE_LIST walk entirely.
    That gap is exactly why index_post_form used to be hand-maintained (and
    drifted - missing wpIgnoreBlankSummary and others). Combines the same
    $request->getXxx() heuristic used for Special: pages with a scan for bare
    'wpXxx' field-name literals (see WP_LITERAL_RE)."""
    path = os.path.join(mw_src, "includes", "EditPage", "EditPage.php")
    if not os.path.isfile(path):
        log.append(f"EditPage: expected file not found at {path}")
        return {"class": "EditPage", "file": None, "method": "not_found", "fields": {}}

    rel_file = os.path.relpath(path, mw_src)
    src = open(path, encoding="utf-8", errors="replace").read()
    names = extract_field_calls(src)
    names |= {n for n in WP_LITERAL_RE.findall(src) if not WP_LITERAL_EXCLUDE_RE.search(n)}
    heuristic = sorted(names)
    return {
        "class": "EditPage", "file": rel_file,
        "method": "heuristic" if heuristic else "none",
        "fields": {name: {"type": "string"} for name in heuristic},
    }


# ---------------------------------------------------------------------------
# index.php action=X POST forms (includes/Actions/*.php)
# ---------------------------------------------------------------------------

# Base/abstract classes - not concrete actions themselves.
_ACTION_BASE_CLASSES = {"Action", "FormAction", "FormlessAction", "ActionEntryPoint", "ActionFactory", "ActionInfo"}

# edit/submit already covered precisely by extract_editpage_fields() (EditPage.php
# is the real source of truth for those forms, not EditAction/SubmitAction).
# FileDeleteAction is WikiFilePage's getActionOverrides() swap-in for File:
# pages under action=delete (see Page/WikiFilePage.php) - same wire-level
# action name and identical fields (inherited from DeleteAction unchanged),
# not a separately submittable action=filedelete.
_ACTION_SKIP = {"EditAction", "SubmitAction", "FileDeleteAction"}

# Pure GET/read-only actions - no side-effecting POST body to model.
_ACTION_VIEW_ONLY = {"ViewAction", "RawAction", "RenderAction", "HistoryAction", "InfoAction", "CreditsAction"}

# ProtectAction/UnprotectAction extend FormlessAction and just call
# Article::protect(), which builds its form in Page/ProtectionForm.php - a
# hand-rolled form class, not a FormAction with getFormFields().
_ACTION_FIELD_FILE_OVERRIDES = {
    "ProtectAction": os.path.join("includes", "Page", "ProtectionForm.php"),
    "UnprotectAction": os.path.join("includes", "Page", "ProtectionForm.php"),
}

# ProtectionForm.php builds field names by string interpolation
# ("mwProtect-level-$action") for each entry in $wgRestrictionTypes, which a
# static regex scan can't see through - default from includes/config-schema.php.
# If a deployment customizes $wgRestrictionTypes, these need updating too.
PROTECT_RESTRICTION_TYPES = ["create", "edit", "move", "upload"]


def extract_index_actions(mw_src, log):
    """Scans includes/Actions/*.php for every concrete Action subclass that
    can be POSTed to index.php (action=X) outside of edit/submit. Mirrors
    extract_special_pages(): getFormFields() (own, or inherited from another
    concrete Action in the same directory - e.g. McrRestoreAction inherits
    McrUndoAction's) when available, else a heuristic $request->getXxx() +
    literal-'wpXxx' scan of whichever file actually builds the form."""
    actions_dir = os.path.join(mw_src, "includes", "Actions")
    result = {}

    for path in sorted(glob.glob(os.path.join(actions_dir, "*.php"))):
        cls = os.path.basename(path)[:-4]
        if cls in _ACTION_BASE_CLASSES or cls in _ACTION_SKIP or cls in _ACTION_VIEW_ONLY:
            continue
        src = open(path, encoding="utf-8", errors="replace").read()
        if not re.search(r"^class\s+" + re.escape(cls) + r"\b", src, re.M):
            continue  # e.g. a file that's only a `class_alias()` shim

        name_m = re.search(r"function getName\(\)\s*\{\s*return\s*'([a-z\-]+)'", src)
        action_name = name_m.group(1) if name_m else cls.lower()

        override = _ACTION_FIELD_FILE_OVERRIDES.get(cls)
        field_path = os.path.join(mw_src, override) if override else path
        field_src = open(field_path, encoding="utf-8", errors="replace").read() if field_path != path else src

        # 1) getFormFields(): own file, else walk up the class's `extends`
        #    chain within includes/Actions/ (McrRestoreAction -> McrUndoAction).
        form_fields = extract_form_fields(field_path, cls, log) if not override else None
        if not form_fields and not override:
            seen, parent_cls, parent_src = {cls}, cls, src
            for _ in range(3):
                m = re.search(r"class\s+" + re.escape(parent_cls) + r"\s+extends\s+(\w+)", parent_src)
                if not m or m.group(1) in _ACTION_BASE_CLASSES or m.group(1) in seen:
                    break
                seen.add(m.group(1))
                parent_path = os.path.join(actions_dir, f"{m.group(1)}.php")
                if not os.path.isfile(parent_path):
                    break
                parent_cls = m.group(1)
                parent_src = open(parent_path, encoding="utf-8", errors="replace").read()
                form_fields = extract_form_fields(parent_path, cls, log)
                if form_fields:
                    field_path = parent_path
                    break

        if form_fields:
            result[cls] = {
                "action": action_name, "file": os.path.relpath(field_path, mw_src),
                "method": "form_fields", "fields": form_fields,
            }
            continue

        # 2) Fallback: heuristic scan of the file that actually builds the form.
        names = extract_field_calls(field_src)
        names |= {n for n in WP_LITERAL_RE.findall(field_src) if not WP_LITERAL_EXCLUDE_RE.search(n)}
        if cls in ("ProtectAction", "UnprotectAction"):
            for rt in PROTECT_RESTRICTION_TYPES:
                names.add(f"mwProtect-level-{rt}")
                names.add(f"mwProtect-expiry-{rt}")
                names.add(f"wpProtectExpirySelection-{rt}")
        heuristic = sorted(names)
        result[cls] = {
            "action": action_name, "file": os.path.relpath(field_path, mw_src),
            "method": "heuristic" if heuristic else "none",
            "fields": {name: {"type": "string"} for name in heuristic},
        }

    return result


# ---------------------------------------------------------------------------

def find_default_mw_src():
    # app-sources/ lives at the repo root, not next to this script (which is
    # under notes/apps/mediawiki/).
    repo_root = find_repo_root(SCRIPT_DIR)
    candidates = sorted(
        p for p in glob.glob(os.path.join(repo_root, "app-sources", "mediawiki", "server", "mediawiki-*"))
        if os.path.isdir(p)
    )
    return candidates[-1] if candidates else None


def main():
    mw_src = sys.argv[1] if len(sys.argv) > 1 else find_default_mw_src()
    if not mw_src or not os.path.isdir(mw_src):
        print("error: could not find a MediaWiki source tree. Pass it explicitly:", file=sys.stderr)
        print("  python3 extract_mediawiki_api.py /path/to/mediawiki-1.46.0", file=sys.stderr)
        sys.exit(1)
    mw_src = os.path.abspath(mw_src)

    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SCRIPT_DIR, "mw-api-extract")
    os.makedirs(out_dir, exist_ok=True)

    api_dir = os.path.join(mw_src, "includes", "Api")
    specials_dir = os.path.join(mw_src, "includes", "Specials")
    special_factory = os.path.join(mw_src, "includes", "SpecialPage", "SpecialPageFactory.php")

    for f in (os.path.join(api_dir, "ApiMain.php"), os.path.join(api_dir, "ApiQuery.php"), special_factory):
        if not os.path.isfile(f):
            print(f"error: expected file not found: {f}", file=sys.stderr)
            print("(is this a MediaWiki core checkout with the includes/Api layout used since ~1.39?)", file=sys.stderr)
            sys.exit(1)

    print(f"MediaWiki source : {mw_src}")
    print(f"Output directory : {out_dir}")
    print()

    log = []
    modules = extract_api_modules(mw_src, api_dir, log)

    api_params_path = os.path.join(out_dir, "api-params.json")
    with open(api_params_path, "w", encoding="utf-8") as f:
        json.dump(modules, f, indent=2, sort_keys=True)

    n_params = sum(len(m["params"]) for m in modules.values())
    print(f"Parsed {len(modules)} modules, {n_params} parameters -> {api_params_path}")

    special_fields = extract_special_pages(special_factory, specials_dir, log)
    special_fields_path = os.path.join(out_dir, "special-fields.json")
    with open(special_fields_path, "w", encoding="utf-8") as f:
        json.dump(special_fields, f, indent=2, sort_keys=True)
    print(f"Scanned {len(special_fields)} Special: pages -> {special_fields_path}")

    editpage_fields = extract_editpage_fields(mw_src, log)
    editpage_fields_path = os.path.join(out_dir, "editpage-fields.json")
    with open(editpage_fields_path, "w", encoding="utf-8") as f:
        json.dump(editpage_fields, f, indent=2, sort_keys=True)
    print(f"Scanned EditPage.php: {len(editpage_fields['fields'])} candidate fields -> {editpage_fields_path}")

    index_actions = extract_index_actions(mw_src, log)
    index_actions_path = os.path.join(out_dir, "index-actions.json")
    with open(index_actions_path, "w", encoding="utf-8") as f:
        json.dump(index_actions, f, indent=2, sort_keys=True)
    n_action_fields = sum(len(a["fields"]) for a in index_actions.values())
    print(f"Scanned {len(index_actions)} index.php actions, {n_action_fields} fields -> {index_actions_path}")

    log_path = os.path.join(out_dir, "extract.log")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log) + "\n")
    print(f"{len(log)} notes on unresolved/dynamic bits -> {log_path}")

    print()
    print("Done. See:")
    print(f"  {api_params_path}")
    print(f"  {special_fields_path}")
    print(f"  {editpage_fields_path}")
    print(f"  {index_actions_path}")
    print(f"  {log_path}")


if __name__ == "__main__":
    main()

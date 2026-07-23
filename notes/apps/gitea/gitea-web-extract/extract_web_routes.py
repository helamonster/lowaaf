#!/usr/bin/env python3
"""
Parses routers/web/web.go's registerWebRoutes(m *web.Router, ...) - the
function Routes() actually delegates the bulk of registration to (confirmed
directly: it spans ~1460 of the file's 1792 lines). A chi-style router
built via nested m.Group("/prefix", func() { ... }, middlewares...) calls,
with routes registered via m.Get/Post/Put/Delete/Patch(path,
[web.Bind(forms.XForm{})], handler), m.Methods("A,B", path, handler), and
m.Combo(path).Get(h1).Post(h2) chains.

Not a real Go parser - a brace/paren-depth-aware line scanner, same spirit
as gen_api_schema.py's parse_go_structs but for router calls instead of
struct fields. One real wrinkle a naive single-pass scanner gets wrong:
several route groups are factored into named closures
(`addWebhookAddRoutes := func() { ... }`) defined once but invoked from
multiple *different* Group() prefixes later - both as a bare `name()` call
inside another Group's body, and as `m.Group(prefix, name, middlewares...)`
(a closure variable used directly as the fn argument, same signature as an
inline func()). Handled as two passes: first collect every such closure's
body, then during route extraction, inline the stored body wherever the
closure is referenced instead of walking its definition site once.

Verified by spot-checking known routes (webhooks, actions
variables/secrets/runners, issues/pulls) before trusting the full output -
the same discipline every extraction script in this project follows.

Explicitly skipped (covered elsewhere or genuinely out of scope):
  - addOwnerRepoGitHTTPRouters(...) / common.AddOwnerRepoGitLFSRoutes(...) -
    hand-written directly in gitea.lua (Phase 3), not re-extracted here.
  - Routes under /api/ (a separate router, api.Routes(), not part of this
    function at all) and /-/ (devtest/healthz/metrics) - low value, skip.

Usage: python3 extract_web_routes.py
"""
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root  # noqa: E402

REPO_ROOT = find_repo_root(SCRIPT_DIR)
GITEA_ROOT = os.path.join(REPO_ROOT, "app-sources", "gitea", "server", "gitea")
WEB_GO = os.path.join(GITEA_ROOT, "routers", "web", "web.go")
OUT_PATH = os.path.join(SCRIPT_DIR, "gitea-web-extracted.json")

VERBS = ("Get", "Post", "Put", "Delete", "Patch", "Head", "Any")

SKIP_CALLS = (
    "addOwnerRepoGitHTTPRouters(",
    "common.AddOwnerRepoGitLFSRoutes(",
)

CLOSURE_DEF_RE = re.compile(r"^(\w+) := func\(\) \{\s*$")


def strip_comment(line):
    in_str = False
    i = 0
    while i < len(line) - 1:
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and c == "/" and line[i + 1] == "/":
            return line[:i]
        i += 1
    return line


def find_func_body(text):
    m = re.search(r"^func registerWebRoutes\(m \*web\.Router,.*\) \{", text, re.MULTILINE)
    start = m.end()
    depth = 1
    i = start
    while depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start:i - 1]


def block_end(lines, i):
    """Given lines[i] is the line right after some `... {` opener (depth
    already at 1 going in), returns the index of the line containing the
    matching closing brace (depth back to 0)."""
    depth = 1
    j = i
    while depth > 0:
        line = strip_comment(lines[j])
        depth += line.count("{") - line.count("}")
        j += 1
    return j - 1


def collect_closures(lines):
    """Pass 1: find every `name := func() { ... }` at any nesting depth,
    return {name: (body_lines, def_line_idx, end_line_idx)}."""
    closures = {}
    i = 0
    while i < len(lines):
        line = strip_comment(lines[i]).strip()
        m = CLOSURE_DEF_RE.match(line)
        if m:
            end = block_end(lines, i + 1)
            closures[m.group(1)] = lines[i + 1:end]
            i = end + 1
            continue
        i += 1
    return closures


def split_top_level_args(s):
    args = []
    depth = 0
    in_str = False
    buf = ""
    i = 0
    while i < len(s):
        c = s[i]
        if in_str:
            buf += c
            if c == '"' and s[i - 1] != "\\":
                in_str = False
        elif c == '"':
            in_str = True
            buf += c
        elif c in "([{":
            depth += 1
            buf += c
        elif c in ")]}":
            depth -= 1
            buf += c
        elif c == "," and depth == 0:
            args.append(buf.strip())
            buf = ""
        else:
            buf += c
        i += 1
    if buf.strip():
        args.append(buf.strip())
    return args


BIND_RE = re.compile(r"web\.Bind\(forms\.(\w+)\{")
PATH_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"$')


def extract_call(name, argstr):
    args = split_top_level_args(argstr)
    if name == "Methods":
        if len(args) < 2:
            return None
        path_arg = args[1]
    else:
        if len(args) < 1:
            return None
        path_arg = args[0]
    pm = PATH_RE.match(path_arg)
    if not pm:
        return None
    path = pm.group(1)
    bind_form = None
    for a in args:
        bm = BIND_RE.search(a)
        if bm:
            bind_form = bm.group(1)
    return path, bind_form


def parse_block(lines, i, prefix, out, skipped, closures, seen_stack):
    """Scans lines[i:] at one nesting level, returns the index just past
    this block's closing brace. `seen_stack` guards against infinite
    recursion if a closure ever referenced itself (none do, but cheap to
    guard)."""
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = strip_comment(raw).strip()

        if line.startswith("}"):
            # This line closes OUR block, but middleware arguments trailing
            # the closing brace can include an inline closure of their own
            # (e.g. "}, reqSignIn, someMiddleware(...), func(ctx *context.Context) {"
            # - a whole extra if-block body follows on subsequent lines
            # before ITS closing "})"). Confirmed live: without accounting
            # for this, the extra unclosed "{" desynced all depth-tracking
            # for everything after it, silently truncating extraction.
            # net+1 is the count of such extra unclosed scopes opened on
            # this same line, after crediting the leading "}" for closing
            # our own block; skip forward past all of them before actually
            # returning control to the caller.
            extra_opens = (line.count("{") - line.count("}")) + 1
            j = i + 1
            while extra_opens > 0 and j < n:
                nxt = strip_comment(lines[j])
                extra_opens += nxt.count("{") - nxt.count("}")
                j += 1
            return j

        if not line:
            i += 1
            continue

        # A closure definition encountered inline (already captured in
        # pass 1) - skip its whole body without disturbing our own depth.
        cm = CLOSURE_DEF_RE.match(line)
        if cm:
            i = block_end(lines, i + 1) + 1
            continue

        if not line.startswith("m."):
            # A bare call to a previously-defined closure, e.g.
            # "addWebhookAddRoutes()" - inline its body at the current prefix.
            bare_m = re.match(r"^(\w+)\(\)\s*$", line)
            if bare_m and bare_m.group(1) in closures and bare_m.group(1) not in seen_stack:
                name = bare_m.group(1)
                parse_block(closures[name], 0, prefix, out, skipped, closures, seen_stack | {name})
                i += 1
                continue
            # Anything else that opens a brace scope we don't specifically
            # handle (if/for blocks, non-zero-arg closures like
            # "openIDSignInEnabled := func(ctx *context.Context) { ... }",
            # struct literals, ...) - skip the *whole* balanced block, not
            # just this one line, or a `}` belonging to it gets mistaken
            # for the end of our own current block (confirmed live: this
            # was silently truncating extraction to ~15 lines).
            net = line.count("{") - line.count("}")
            if net > 0:
                i = block_end(lines, i + 1) + 1
            else:
                i += 1
            continue

        if any(sk in line for sk in SKIP_CALLS):
            skipped.append(("mounted-router", line[:80]))
            i += 1
            continue

        # m.PathGroup(pattern, func(g *web.RouterPathGroup) { g.MatchPath(...) })
        # - a completely different router API (wildcard path matching, its
        # own g.MatchPath(...) call shape) used exactly once in this file
        # (the /compare/* diff/patch download endpoints). Not worth
        # modeling for one occurrence - hand-added to gitea.lua directly
        # instead - but its body MUST still be depth-tracked and skipped
        # correctly, or the unclosed "{" from its inline closure desyncs
        # every subsequent line's block-nesting (confirmed live: silently
        # truncated extraction well before the end of the file).
        if line.startswith("m.PathGroup("):
            skipped.append(("path-group-not-modeled", line[:100]))
            net = line.count("{") - line.count("}")
            i = block_end(lines, i + 1) + 1 if net > 0 else i + 1
            continue

        group_m = re.match(r'm\.Group\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*(func\(\)\s*\{|(\w+))', line)
        if group_m:
            sub_prefix = prefix + group_m.group(1)
            if group_m.group(2) == "func() {" or group_m.group(2).startswith("func()"):
                i = parse_block(lines, i + 1, sub_prefix, out, skipped, closures, seen_stack)
            else:
                # m.Group("path", someClosureName, middlewares...) - the
                # closure var used directly as the fn argument.
                cname = group_m.group(3)
                if cname in closures and cname not in seen_stack:
                    parse_block(closures[cname], 0, sub_prefix, out, skipped, closures, seen_stack | {cname})
                else:
                    skipped.append(("unknown-group-fn", line[:100]))
                i += 1
            continue

        verb_m = re.match(r"m\.(" + "|".join(VERBS) + r")\(", line)
        methods_m = re.match(r"m\.Methods\(", line)
        combo_m = re.match(r'm\.Combo\(\s*"((?:[^"\\]|\\.)*)"', line)

        if verb_m or methods_m:
            depth = line.count("(") - line.count(")")
            full = line
            j = i
            while depth > 0 and j + 1 < n:
                j += 1
                nxt = strip_comment(lines[j]).strip()
                full += " " + nxt
                depth += nxt.count("(") - nxt.count(")")
            call_m = re.match(r"m\.(\w+)\((.*)\)\s*$", full)
            if call_m:
                name, argstr = call_m.group(1), call_m.group(2)
                result = extract_call(name, argstr)
                if result:
                    path, bind_form = result
                    if name == "Methods":
                        args = split_top_level_args(argstr)
                        methods = [x.strip() for x in args[0].strip('"').split(",")]
                    else:
                        methods = [name]
                    out.append({"methods": methods, "path": prefix + path, "form": bind_form})
                else:
                    skipped.append(("unparsed-call", full[:100]))
            else:
                skipped.append(("unmatched-call", full[:100]))
            i = j + 1
            continue

        if combo_m:
            base_path = prefix + combo_m.group(1)
            depth = line.count("(") - line.count(")")
            full = line
            j = i
            while depth > 0 and j + 1 < n:
                j += 1
                nxt = strip_comment(lines[j]).strip()
                full += " " + nxt
                depth += nxt.count("(") - nxt.count(")")
            for seg_m in re.finditer(r"\.(" + "|".join(VERBS) + r")\(((?:[^()]|\([^()]*\))*)\)", full):
                method, argstr = seg_m.group(1), seg_m.group(2)
                bind_form = None
                bm = BIND_RE.search(argstr)
                if bm:
                    bind_form = bm.group(1)
                out.append({"methods": [method], "path": base_path, "form": bind_form})
            i = j + 1
            continue

        # Safety net: any other "m."-prefixed construct not recognized
        # above (the codebase surprised us twice already - m.PathGroup
        # above, and non-m. closures before that - both silently desynced
        # depth-tracking for everything downstream until specifically
        # handled). If it opens an unclosed brace, skip its whole body
        # rather than just this line.
        net = line.count("{") - line.count("}")
        if net > 0:
            skipped.append(("unrecognized-m-construct", line[:100]))
            i = block_end(lines, i + 1) + 1
        else:
            i += 1
    return i


def main():
    text = open(WEB_GO, encoding="utf-8").read()
    body = find_func_body(text)
    lines = body.splitlines()

    closures = collect_closures(lines)

    out = []
    skipped = []
    parse_block(lines, 0, "", out, skipped, closures, frozenset())

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"routes": out}, f, indent=2)

    print(f"Wrote {OUT_PATH}: {len(out)} route entries ({len(closures)} named closures inlined)")
    if skipped:
        by_kind = {}
        for kind, _ in skipped:
            by_kind[kind] = by_kind.get(kind, 0) + 1
        print(f"Skipped {len(skipped)} lines: {by_kind}")
        print("First 15 skipped:")
        for kind, text_ in skipped[:15]:
            print(f"  [{kind}] {text_}")


if __name__ == "__main__":
    main()

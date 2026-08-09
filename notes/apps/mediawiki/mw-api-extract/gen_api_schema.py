#!/usr/bin/env python3
"""
Generates rootfs/etc/openresty/waf/apps/mediawiki/api_schema.lua from
paraminfo.json (dump_paraminfo.py's live introspection of a running
MediaWiki instance's action=paraminfo endpoint) - see dump_paraminfo.py's
own header for why this replaced regex-parsing PHP source
(gen_all_tiers.py + integrate_api_tiers.py, both deleted) for the api.php
side. Also replaces the hand-written HAND_WRITTEN_ACTIONS table that used
to cover AuthManager-driven actions (login/clientlogin/createaccount/...):
paraminfo resolves those correctly and uniformly, including a `token` field
that 6 of the 11 hand-written entries were missing (a real bug, found by
cross-referencing against this same live data before this migration).

One thing paraminfo can't tell you: which enum-typed fields are genuinely
config/extension-dependent (their live values reflect the DUMPING
environment's specific config - e.g. search backend or
$wgRestrictionLevels - not necessarily any other deployment's).
Cross-references extract_mediawiki_api.py's existing static
`dynamic_type_expr` detection (already present in api-params.json,
unchanged by this migration) to flag those fields and fall back to a
generic bounded string instead of trusting the live enum values verbatim.

Also implements the MW_WAF_API_HIGH_LIMITS env var toggle: for
type=limit/integer fields, paraminfo gives both a normal min/max AND a
higher highmax for apihighlimits-privileged users (bots, sysops). Off by
default (use the lower cap) - a one-time deployment-config choice made when
the WAF is set up, not something inferred from live traffic; set
MW_WAF_API_HIGH_LIMITS=1 to regenerate using the higher cap instead.

Usage: MW_WAF_API_HIGH_LIMITS=0|1 python3 gen_api_schema.py
"""
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root, lua_str, field_key  # noqa: E402

ROOT = find_repo_root(SCRIPT_DIR)
OUT_PATH = os.path.join(ROOT, "rootfs/etc/openresty/waf/apps/mediawiki/api_schema.lua")
PARAMINFO_PATH = os.path.join(SCRIPT_DIR, "paraminfo.json")
API_PARAMS_PATH = os.path.join(SCRIPT_DIR, "api-params.json")

USE_HIGH_LIMITS = os.environ.get("MW_WAF_API_HIGH_LIMITS", "0") == "1"

STRING_DEFAULT_MAX = 512
TEXT_MAX = 1024 * 1024
MULTI_MAX = 2048

SKIP_GROUPS = {"format"}  # output-format modules (json/xml/...) - no request params to model


def enum_table(values):
    return "{ " + ", ".join(f"[{lua_str(v)}]=true" for v in values) + " }"


def bare_key(path):
    """paraminfo paths prefix query submodules with "query+" (e.g.
    "query+prefixsearch"); api-params.json (this repo's own static scan)
    keys everything bare ("prefixsearch"). Normalizes to the bare form,
    used both as this script's own mw_query_submodules[kind] key and to
    cross-reference api-params.json's dynamic_type_expr flags."""
    if path.startswith("query+"):
        return path[len("query+"):]
    return path


def load_dynamic_enum_fields():
    """Cross-references api-params.json (extract_mediawiki_api.py's static
    scan, unchanged by this migration) for fields it flagged as
    dynamic_type_expr - PARAM_TYPE built from a runtime expression the
    static parser found but couldn't resolve to a literal array (e.g.
    "search"'s srsort <- $this->searchEngineFactory->create()->getValidSorts()).
    Returns {module_bare_key: {wire_field_name, ...}}; gen_api_schema.py
    falls back to a generic bounded string for these instead of trusting
    paraminfo's live-resolved enum values, since those values are specific
    to whatever environment was dumped, not necessarily portable to a
    different deployment's config."""
    if not os.path.exists(API_PARAMS_PATH):
        return {}
    data = json.load(open(API_PARAMS_PATH))
    flagged = {}
    for module_key, mod in data.items():
        for pname, spec in mod.get("params", {}).items():
            if "dynamic_type_expr" in spec:
                flagged.setdefault(module_key, set()).add(pname)
    return flagged


def field_lua(wire_name, param, dynamic_fields, indent):
    t = param.get("type", "string")
    required = "required" in param
    multi = "multi" in param
    sensitive = "sensitive" in param
    comment = ""

    if isinstance(t, list):
        if wire_name in dynamic_fields:
            comment = "  -- dynamic enum (config/extension-dependent), left generic"
            inner = f"T.string({{ max={MULTI_MAX if multi else STRING_DEFAULT_MAX} }})"
        elif multi:
            inner = f"T.string({{ max={MULTI_MAX} }})"
            flat_vals = ", ".join(re.sub(r"\s+", " ", v).strip() for v in t)
            comment = f"  -- pipe-separated list of: {flat_vals}"
        else:
            max_len = max([len(v) for v in t] + [1])
            inner = f"T.string({{ max={max_len}, enum={enum_table(t)} }})"
    elif t == "boolean":
        # MediaWiki API booleans are presence-based (any value = true, absent
        # = false) and arrive as plain query/form strings here, never a real
        # JSON boolean - T.boolean() would wrongly require type(v)=="boolean".
        inner = "T.string({ max=8 })"
    elif t in ("integer", "limit"):
        opts = ["integer=true"]
        lo = param.get("min")
        # Default (USE_HIGH_LIMITS off): always the lower cap, full stop - no
        # fallback to highmax, that would silently invert the policy. When
        # on: prefer highmax, but fields that aren't apihighlimits-gated at
        # all only have "max" to begin with, so fall back to that.
        hi = param.get("highmax", param.get("max")) if USE_HIGH_LIMITS else param.get("max")
        if lo is not None:
            opts.append(f"min={lo}")
        if hi is not None:
            opts.append(f"max={hi}")
        inner = f"T.number_query({{ {', '.join(opts)} }})"
    elif t == "text":
        inner = f"T.string({{ max={TEXT_MAX} }})"
    elif t == "password":
        inner = f"T.string({{ max=256 }})"
    else:
        cap = MULTI_MAX if multi else STRING_DEFAULT_MAX
        inner = f"T.string({{ max={cap} }})"
        if t not in ("string",):
            comment = f"  -- mediawiki type: {t}"

    if sensitive and "sensitive" not in comment:
        comment = (comment + "; sensitive") if comment else "  -- sensitive"
    if "tokentype" in param:
        tt = param["tokentype"]
        comment = (comment + f"; token type: {tt}") if comment else f"  -- token type: {tt}"

    if not required:
        inner = f"T.nullable({inner})"

    return f"{indent}{field_key(wire_name)} = {inner},{comment}"


def dynamic_auth_param(field):
    """Adapts one meta=authmanagerinfo field dict (dump_paraminfo.py's
    _dynamic_auth_fields, fetched live for clientlogin/createaccount/
    changeauthenticationdata/linkaccount - see that script's own header for
    why these need a separate live call at all) to the shape field_lua()
    expects from a regular paraminfo parameter. Only two conventions
    actually differ: authmanagerinfo flags optionality via "optional"
    (paraminfo/field_lua use "required", the inverse - so its ABSENCE here
    means required), and its "checkbox"/"password" type names map directly
    onto field_lua's existing "boolean"/"password" branches (both already
    handle the static-parameter case identically)."""
    t = field.get("type", "string")
    if t == "checkbox":
        t = "boolean"
    param = {"type": t}
    if "optional" not in field:
        param["required"] = ""
    if "sensitive" in field:
        param["sensitive"] = ""
    return param


def emit_module_fields(mod, dynamic_fields, indent):
    prefix = mod.get("prefix") or ""
    lines = []
    seen = set()
    for param in sorted(mod.get("parameters", []), key=lambda p: p.get("name", "")):
        name = param.get("name")
        if not name or "{s}" in name or "{slot}" in name:
            # Templated parameters (e.g. "rvcontentformat-{slot}") aren't a
            # single concrete field name - the base "rvcontentformat" entry
            # already covers the common case; skip the template variants
            # rather than emitting a literal, never-matching "-{slot}" key.
            continue
        # Apply prefix unconditionally, regardless of module group. Most
        # group="action" modules have an empty prefix (a no-op here), but
        # confirmed live against paraminfo.json: clientlogin ("login"),
        # login ("lg"), createaccount ("create"), changeauthenticationdata
        # ("changeauth"), and linkaccount ("link") are action modules that
        # DO carry a real prefix MediaWiki applies to every one of their
        # wire parameter names (e.g. clientlogin's "returnurl"/"token" are
        # really "loginreturnurl"/"logintoken") - a previous version of this
        # function special-cased is_action to skip prefixing entirely on the
        # false assumption that only query submodules use one, which left
        # those 5 modules' generated schemas rejecting every real request as
        # "unknown key" (confirmed live: blocked a real clientlogin login).
        wire_name = prefix + name
        if wire_name in seen:
            continue
        seen.add(wire_name)
        lines.append(field_lua(wire_name, param, dynamic_fields, indent))

    # AuthManager-injected fields (username/password/... on clientlogin etc.)
    # are NOT prefixed - confirmed live, see dump_paraminfo.py's header.
    for name, field in sorted(mod.get("_dynamic_auth_fields", {}).items()):
        if name in seen:
            continue
        seen.add(name)
        lines.append(field_lua(name, dynamic_auth_param(field), dynamic_fields, indent))
    return "\n".join(lines)


def main():
    if not os.path.exists(PARAMINFO_PATH):
        print(f"ERROR: {PARAMINFO_PATH} not found - run mw-dump-paraminfo first "
              f"(requires the Docker test stack up)", file=sys.stderr)
        sys.exit(1)

    paraminfo = json.load(open(PARAMINFO_PATH))
    modules = paraminfo["modules"]
    dynamic_fields = load_dynamic_enum_fields()

    actions = {}
    submodules = {"prop": {}, "list": {}, "meta": {}}
    for path, mod in modules.items():
        group = mod.get("group")
        if group in SKIP_GROUPS:
            continue
        key = bare_key(path)
        flagged = dynamic_fields.get(key, set())
        if group == "action":
            actions[key] = mod, flagged
        elif group in submodules:
            submodules[group][key] = mod, flagged

    out = []
    out.append("-- Generated by gen_api_schema.py from paraminfo.json (live introspection -")
    out.append("-- see dump_paraminfo.py/gen_api_schema.py's own headers for why) - do not")
    out.append("-- hand-edit, re-run the generator.")
    out.append("local T = require \"waf.types\"")
    out.append("")
    out.append("-- Shallow-merges one or more {key=validator} tables into a new table; later")
    out.append("-- tables' keys win on conflict.")
    out.append("local function merge(...)")
    out.append("  local out = {}")
    out.append("  for _, t in ipairs({...}) do")
    out.append("    for k, v in pairs(t) do out[k] = v end")
    out.append("  end")
    out.append("  return out")
    out.append("end")
    out.append("")
    out.append("-- pairs() iteration order over a table's string-keyed hash part is not")
    out.append("-- guaranteed stable across separate Lua process starts. Below, several")
    out.append("-- loops fold many actions'/submodules' field tables into one flat union,")
    out.append("-- where a field name shared by two actions with different constraints")
    out.append("-- (e.g. 'filename') resolves to whichever one the loop visits last - so")
    out.append("-- an unordered pairs() there made the union's winner for such fields (and")
    out.append("-- therefore the offline test suite's generated case count) vary between")
    out.append("-- runs, confirmed by diffing two consecutive runs of the same generated")
    out.append("-- file. sorted_pairs() makes that resolution repeatable.")
    out.append("local function sorted_pairs(t)")
    out.append("  local keys = {}")
    out.append("  for k in pairs(t) do keys[#keys + 1] = k end")
    out.append("  table.sort(keys)")
    out.append("  local i = 0")
    out.append("  return function()")
    out.append("    i = i + 1")
    out.append("    if keys[i] ~= nil then return keys[i], t[keys[i]] end")
    out.append("  end")
    out.append("end")
    out.append("")
    out.append("local mw_api_actions = {")
    for key in sorted(actions):
        mod, flagged = actions[key]
        out.append(f"  -- {key} ({mod.get('classname', '?')})")
        out.append(f"  {field_key(key)} = {{")
        fields = emit_module_fields(mod, flagged, "    ")
        if fields:
            out.append(fields)
        out.append("  },")
    out.append("}")
    out.append("")
    out.append("local mw_query_submodules = {")
    for kind in ("prop", "list", "meta"):
        out.append(f"  {kind} = {{")
        for key in sorted(submodules[kind]):
            mod, flagged = submodules[kind][key]
            out.append(f"    -- {key} ({mod.get('classname', '?')})")
            out.append(f"    {field_key(key)} = {{")
            fields = emit_module_fields(mod, flagged, "      ")
            if fields:
                out.append(fields)
            out.append("    },")
        out.append("  },")
    out.append("}")
    out.append("")
    out.append("local function split_pipe_list(s)")
    out.append("  local out = {}")
    out.append("  if type(s) ~= \"string\" then return out end")
    out.append("  for part in (s .. \"|\"):gmatch(\"([^|]*)|\") do")
    out.append("    if part ~= \"\" then out[#out + 1] = part end")
    out.append("  end")
    out.append("  return out")
    out.append("end")
    out.append("")
    out.append("-- Unions the field sets of every prop=/list=/meta= submodule named in a")
    out.append("-- query request (each of those args may itself list multiple pipe-separated")
    out.append("-- submodules, e.g. prop=info|revisions).")
    out.append("local function resolve_query_submodule_fields(v)")
    out.append("  local fields = {}")
    out.append("  for _, kind in ipairs({ \"prop\", \"list\", \"meta\" }) do")
    out.append("    for _, name in ipairs(split_pipe_list(v[kind])) do")
    out.append("      local sub = mw_query_submodules[kind] and mw_query_submodules[kind][name]")
    out.append("      if sub then fields = merge(fields, sub) end")
    out.append("    end")
    out.append("  end")
    out.append("  -- generator=X reuses submodule X's own params (X must be prop= or list=")
    out.append("  -- eligible, i.e. extend ApiQueryGeneratorBase), but every wire name gets an")
    out.append("  -- extra leading 'g' (list=prefixsearch's pssearch becomes")
    out.append("  -- generator=prefixsearch's gpssearch). Fixed, uniform ApiPageSet")
    out.append("  -- convention, not something each submodule declares in its own")
    out.append("  -- getAllowedParams() (or paraminfo dump).")
    out.append("  if v.generator then")
    out.append("    local gen_sub = (mw_query_submodules.list and mw_query_submodules.list[v.generator])")
    out.append("                 or (mw_query_submodules.prop and mw_query_submodules.prop[v.generator])")
    out.append("    if gen_sub then")
    out.append("      for key, validator in pairs(gen_sub) do")
    out.append("        fields[\"g\" .. key] = validator")
    out.append("      end")
    out.append("    end")
    out.append("  end")
    out.append("  return fields")
    out.append("end")
    out.append("")
    out.append("local mw_api_action_fields_union = {}")
    out.append("for _, fields in sorted_pairs(mw_api_actions) do")
    out.append("  mw_api_action_fields_union = merge(mw_api_action_fields_union, fields)")
    out.append("end")
    out.append("local mw_query_submodule_fields_union = {}")
    out.append("for _, kind_fields in sorted_pairs(mw_query_submodules) do")
    out.append("  for _, fields in sorted_pairs(kind_fields) do")
    out.append("    mw_query_submodule_fields_union = merge(mw_query_submodule_fields_union, fields)")
    out.append("  end")
    out.append("end")
    out.append("-- T.with_check validates the base object schema (this union) BEFORE")
    out.append("-- api_check ever runs, so generator=X's g-prefixed field names (see")
    out.append("-- resolve_query_submodule_fields() above) need to be allowed here too, not")
    out.append("-- just in the per-request dynamic lookup - otherwise the base schema rejects")
    out.append("-- them before api_check's own generator= narrowing gets a chance.")
    out.append("for _, kind in ipairs({ \"prop\", \"list\" }) do")
    out.append("  for _, fields in sorted_pairs(mw_query_submodules[kind] or {}) do")
    out.append("    for key, validator in pairs(fields) do")
    out.append("      mw_query_submodule_fields_union[\"g\" .. key] = validator")
    out.append("    end")
    out.append("  end")
    out.append("end")
    out.append("")
    out.append("return {")
    out.append("  mw_api_actions = mw_api_actions,")
    out.append("  mw_query_submodules = mw_query_submodules,")
    out.append("  resolve_query_submodule_fields = resolve_query_submodule_fields,")
    out.append("  mw_api_action_fields_union = mw_api_action_fields_union,")
    out.append("  mw_query_submodule_fields_union = mw_query_submodule_fields_union,")
    out.append("}")

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

    n_sub = sum(len(v) for v in submodules.values())
    print(f"Wrote {OUT_PATH} ({len(actions)} actions, {n_sub} query submodules, "
          f"{sum(len(v) for v in dynamic_fields.values())} fields flagged config-dependent, "
          f"high_limits={'on' if USE_HIGH_LIMITS else 'off'})")


if __name__ == "__main__":
    main()

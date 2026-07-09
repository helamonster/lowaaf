#!/usr/bin/env python3
"""
One-shot integrator: reads mw-api-extract/api-params.json and regenerates the
ENTIRE api.php schema section of mediawiki.lua (api_common through api_schema),
replacing the marker-bounded span in place. Covers Tiers 1-5 (all action
modules + all query prop/list/meta submodules) in a single pass.

Usage: python3 integrate_api_tiers.py
"""
import json, re, sys, os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_repo_root(start):
    d = start
    while d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, "rootfs", "etc", "openresty", "waf")):
            return d
        d = os.path.dirname(d)
    raise RuntimeError("could not find repo root above " + start)


ROOT = _find_repo_root(SCRIPT_DIR)
JSON_PATH = os.path.join(SCRIPT_DIR, "api-params.json")
LUA_PATH = os.path.join(ROOT, "rootfs/etc/openresty/waf/apps/mediawiki.lua")

STRING_DEFAULT_MAX = 512
TEXT_MAX = 1024 * 1024
MULTI_MAX = 2048

# Actions handled by hand in Tier 1 (auth/session) - these delegate to
# ApiAuthManagerHelper or have config-dependent shapes that the static
# extractor can't fully resolve, so they're kept as hand-written entries
# rather than overwritten by the mechanical generator.
HAND_WRITTEN_ACTIONS = {
    "login", "clientlogin", "createaccount", "linkaccount", "unlinkaccount",
    "changeauthenticationdata", "removeauthenticationdata", "resetpassword",
    "validatepassword", "checktoken", "acquiretempusername", "clearhasmsg", "logout",
}

def lua_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

def enum_table(values):
    return "{ " + ", ".join(f"[{lua_str(v)}]=true" for v in values) + " }"

def field_lua(name, spec, indent):
    t = spec.get("type", "string")
    ismulti = spec.get("ismulti", False)
    required = spec.get("required", False)
    comment = ""

    if "dynamic_type_expr" in spec:
        flat_expr = re.sub(r"\s+", " ", spec["dynamic_type_expr"]).strip()
        comment = f"  -- dynamic enum from {flat_expr!r}, left generic"
    elif "note" in spec:
        comment = f"  -- {spec['note']}"

    if t == "enum":
        vals = spec.get("enum", [])
        max_len = max([len(v) for v in vals] + [1])
        if ismulti:
            inner = f"T.string({{ max={MULTI_MAX} }})"
            flat_vals = ", ".join(re.sub(r"\s+", " ", v).strip() for v in vals)
            comment = comment or f"  -- pipe-separated list of: {flat_vals}"
        else:
            inner = f"T.string({{ max={max_len}, enum={enum_table(vals)} }})"
    elif t == "boolean":
        # MediaWiki API booleans are presence-based (any value = true, absent
        # = false) and arrive as plain query/form strings here, never a real
        # JSON boolean - T.boolean() would wrongly require type(v)=="boolean".
        inner = "T.string({ max=8 })"
    elif t in ("integer", "limit"):
        opts = ["integer=true"]
        if "param_min" in spec: opts.append(f"min={spec['param_min']}")
        if "param_max" in spec: opts.append(f"max={spec['param_max']}")
        inner = f"T.number_query({{ {', '.join(opts)} }})"
    elif t == "text":
        inner = f"T.string({{ max={TEXT_MAX} }})"
    elif t == "password":
        inner = f"T.string({{ max=256 }})"
        comment = comment or "  -- sensitive"
    elif t in ("user", "timestamp", "namespace", "tags", "upload", "raw", "submodule"):
        cap = MULTI_MAX if ismulti else STRING_DEFAULT_MAX
        inner = f"T.string({{ max={cap} }})"
        comment = comment or f"  -- mediawiki type: {t}"
    else:
        cap = MULTI_MAX if ismulti else STRING_DEFAULT_MAX
        inner = f"T.string({{ max={cap} }})"

    if not required:
        inner = f"T.nullable({inner})"

    key = name if re.match(r"^[A-Za-z_]\w*$", name) and name not in ("end", "continue", "type", "repeat", "function", "assert") else f"[{lua_str(name)}]"
    return f"{indent}{key} = {inner},{comment}"

def emit_fields(params, indent):
    return "\n".join(field_lua(n, s, indent) for n, s in sorted(params.items()))

def main():
    data = json.load(open(JSON_PATH))

    action_keys = sorted(k for k, v in data.items() if v["kind"] == "action" and k not in HAND_WRITTEN_ACTIONS)
    prop_keys = sorted(k for k, v in data.items() if v["kind"] == "prop")
    list_keys = sorted(k for k, v in data.items() if v["kind"] == "list")
    meta_keys = sorted(k for k, v in data.items() if v["kind"] == "meta")

    out = []
    out.append("-- Precisely-modeled per-action extra fields. Tier 1: auth/session actions.")
    out.append("-- clientlogin/createaccount/linkaccount/(un)linkaccount/removeauthenticationdata/")
    out.append("-- changeauthenticationdata all delegate to ApiAuthManagerHelper::getStandardParams(),")
    out.append("-- which offers a fixed menu of fields; each caller picks a subset of it")
    out.append("-- (see includes/Api/ApiAuthManagerHelper.php).")
    out.append("local mw_api_actions = {")
    out.append("  login = {")
    out.append("    domain   = T.nullable(T.string({ max=512 })),")
    out.append("    name     = T.nullable(T.string({ max=512 })),")
    out.append("    password = T.nullable(T.string({ max=256 })),  -- sensitive")
    out.append("    token    = T.nullable(T.string({ max=512 })),  -- sensitive; BC allows omitting it")
    out.append("  },")
    out.append("  clientlogin = {")
    out.append("    requests           = T.nullable(T.string({ max=8192 })),  -- serialized AuthenticationRequest[]")
    out.append("    messageformat      = T.nullable(T.string({ max=16, enum={ html=true, wikitext=true, raw=true, none=true } })),")
    out.append("    mergerequestfields = T.nullable(T.string({ max=8 })),")
    out.append("    preservestate      = T.nullable(T.string({ max=8 })),")
    out.append("    returnurl          = T.nullable(T.string({ max=1024 })),")
    out.append("    [\"continue\"]       = T.nullable(T.string({ max=8 })),")
    out.append("    -- Flat PasswordAuthenticationRequest fields - the plain username/password")
    out.append("    -- login flow MediaWiki's own API help documents as the primary clientlogin")
    out.append("    -- example, distinct from the JS client's 'requests' bundling above.")
    out.append("    username      = T.nullable(T.string({ max=512 })),")
    out.append("    password      = T.nullable(T.string({ max=256 })),  -- sensitive")
    out.append("    logintoken    = T.nullable(T.string({ max=512 })),  -- sensitive")
    out.append("    loginreturnurl = T.nullable(T.string({ max=1024 })),")
    out.append("    logincontinue = T.nullable(T.string({ max=8 })),")
    out.append("    OATHToken     = T.nullable(T.string({ max=32 })),  -- 2FA continuation")
    out.append("  },")
    out.append("  createaccount = {")
    out.append("    requests           = T.nullable(T.string({ max=8192 })),")
    out.append("    messageformat      = T.nullable(T.string({ max=16, enum={ html=true, wikitext=true, raw=true, none=true } })),")
    out.append("    mergerequestfields = T.nullable(T.string({ max=8 })),")
    out.append("    preservestate      = T.nullable(T.string({ max=8 })),")
    out.append("    returnurl          = T.nullable(T.string({ max=1024 })),")
    out.append("    [\"continue\"]       = T.nullable(T.string({ max=8 })),")
    out.append("    -- Flat fields - see includes/Api/ApiAMCreateAccount.php's own documented example.")
    out.append("    username        = T.nullable(T.string({ max=512 })),")
    out.append("    password        = T.nullable(T.string({ max=256 })),  -- sensitive")
    out.append("    retype          = T.nullable(T.string({ max=256 })),  -- sensitive")
    out.append("    email           = T.nullable(T.string({ max=320 })),")
    out.append("    realname        = T.nullable(T.string({ max=256 })),")
    out.append("    createtoken     = T.nullable(T.string({ max=512 })),  -- sensitive")
    out.append("    createreturnurl = T.nullable(T.string({ max=1024 })),")
    out.append("  },")
    out.append("  linkaccount = {")
    out.append("    requests           = T.nullable(T.string({ max=8192 })),")
    out.append("    messageformat      = T.nullable(T.string({ max=16, enum={ html=true, wikitext=true, raw=true, none=true } })),")
    out.append("    mergerequestfields = T.nullable(T.string({ max=8 })),")
    out.append("    returnurl          = T.nullable(T.string({ max=1024 })),")
    out.append("    [\"continue\"]       = T.nullable(T.string({ max=8 })),")
    out.append("  },")
    out.append("  unlinkaccount            = { request = T.nullable(T.string({ max=8192 })) },")
    out.append("  changeauthenticationdata = { request = T.nullable(T.string({ max=8192 })) },")
    out.append("  removeauthenticationdata = { request = T.nullable(T.string({ max=8192 })) },")
    out.append("  resetpassword = {")
    out.append("    user  = T.nullable(T.string({ max=256 })),")
    out.append("    email = T.nullable(T.string({ max=320 })),")
    out.append("  },")
    out.append("  validatepassword = {")
    out.append("    password = T.string({ max=256 }),  -- required, sensitive")
    out.append("    user     = T.nullable(T.string({ max=256 })),")
    out.append("    email    = T.nullable(T.string({ max=320 })),")
    out.append("    realname = T.nullable(T.string({ max=256 })),")
    out.append("  },")
    out.append("  checktoken = {")
    out.append("    type = T.string({ max=32, enum={")
    out.append("      csrf=true, watch=true, patrol=true, rollback=true, userrights=true,")
    out.append("      login=true, createaccount=true,")
    out.append("    } }),  -- core's default token-type salts; extensions can register more via a hook (not covered)")
    out.append("    token       = T.string({ max=512 }),  -- sensitive")
    out.append("    maxtokenage = T.nullable(T.number_query({ integer=true })),")
    out.append("  },")
    out.append("  -- acquiretempusername, clearhasmsg, and logout take no parameters at all.")
    out.append("  acquiretempusername = {},")
    out.append("  clearhasmsg          = {},")
    out.append("  logout               = {},")
    out.append("")
    out.append("  -- Tiers 2 + 5: mechanically extracted from includes/Api/Api*.php via")
    out.append("  -- extract-mediawiki-api.sh + mw-api-extract/integrate_api_tiers.py.")
    for key in action_keys:
        mod = data[key]
        out.append(f"  -- {key} ({mod['class']}) -- {mod['file']}")
        out.append(f"  {key} = {{")
        out.append(emit_fields(mod["params"], "    "))
        out.append("  },")
    out.append("}")
    out.append("")
    out.append("-- action=query submodules, looked up by name from prop=/list=/meta= (each")
    out.append("-- pipe-separated and multi-valued) rather than from `action` directly - see")
    out.append("-- resolve_query_submodule_fields() below. Mechanically extracted the same way.")
    out.append("local mw_query_submodules = {")
    for kind, keys in (("prop", prop_keys), ("list", list_keys), ("meta", meta_keys)):
        out.append(f"  {kind} = {{")
        for key in keys:
            mod = data[key]
            out.append(f"    -- {key} ({mod['class']}) -- {mod['file']}")
            out.append(f"    {key} = {{")
            out.append(emit_fields(mod["params"], "      "))
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
    out.append("  -- eligible, i.e. extend ApiQueryGeneratorBase - ~24 core submodules do:")
    out.append("  -- categorymembers, search, prefixsearch, images, links, ... ), but every")
    out.append("  -- wire name gets an extra leading 'g' (list=prefixsearch's pssearch becomes")
    out.append("  -- generator=prefixsearch's gpssearch). Fixed, uniform ApiPageSet convention,")
    out.append("  -- not something each submodule declares in its own getAllowedParams().")
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
    out.append("for _, fields in pairs(mw_api_actions) do")
    out.append("  mw_api_action_fields_union = merge(mw_api_action_fields_union, fields)")
    out.append("end")
    out.append("local mw_query_submodule_fields_union = {}")
    out.append("for _, kind_fields in pairs(mw_query_submodules) do")
    out.append("  for _, fields in pairs(kind_fields) do")
    out.append("    mw_query_submodule_fields_union = merge(mw_query_submodule_fields_union, fields)")
    out.append("  end")
    out.append("end")
    out.append("-- T.with_check validates the base object schema (this union) BEFORE")
    out.append("-- api_check ever runs, so generator=X's g-prefixed field names (see")
    out.append("-- resolve_query_submodule_fields() below) need to be allowed here too,")
    out.append("-- not just in the per-request dynamic lookup - otherwise the base schema")
    out.append("-- rejects them before api_check's own generator= narrowing gets a chance.")
    out.append("for _, kind in ipairs({ \"prop\", \"list\" }) do")
    out.append("  for _, fields in pairs(mw_query_submodules[kind] or {}) do")
    out.append("    for key, validator in pairs(fields) do")
    out.append("      mw_query_submodule_fields_union[\"g\" .. key] = validator")
    out.append("    end")
    out.append("  end")
    out.append("end")

    new_middle = "\n".join(out)

    src = open(LUA_PATH, encoding="utf-8").read()

    start_marker = "-- Precisely-modeled per-action extra fields. Tier 1: auth/session actions."
    # Must extend through BOTH generated union-building loops - new_middle
    # (built above) ends with mw_query_submodule_fields_union's loop too, not
    # just mw_api_action_fields_union's. Matching only the first one used to
    # leave every previous run's copy of the second loop sitting untouched in
    # the "preserved" tail, so re-running this script kept adding another
    # local mw_query_submodule_fields_union = {} on top of the last one.
    end_marker_pat = re.compile(
        r"local mw_api_action_fields_union = \{\}\nfor _, fields in pairs\(mw_api_actions\) do\n"
        r"  mw_api_action_fields_union = merge\(mw_api_action_fields_union, fields\)\nend\n"
        r"local mw_query_submodule_fields_union = \{\}\nfor _, kind_fields in pairs\(mw_query_submodules\) do\n"
        r"  for _, fields in pairs\(kind_fields\) do\n"
        r"    mw_query_submodule_fields_union = merge\(mw_query_submodule_fields_union, fields\)\n"
        r"  end\nend\n"
        # The g-prefix widening loop (added after the fact) - optional so this
        # still matches the very first re-run against an older file that
        # doesn't have it yet, not just subsequent idempotent re-runs.
        r"(?:(?:-- .*\n)*"
        r"for _, kind in ipairs\(\{ \"prop\", \"list\" \}\) do\n"
        r"  for _, fields in pairs\(mw_query_submodules\[kind\] or \{\}\) do\n"
        r"    for key, validator in pairs\(fields\) do\n"
        r"      mw_query_submodule_fields_union\[\"g\" \.\. key\] = validator\n"
        r"    end\n"
        r"  end\nend\n)?"
    )

    start_idx = src.index(start_marker)
    m = end_marker_pat.search(src, start_idx)
    if not m:
        print("ERROR: could not find end marker for mw_query_submodule_fields_union block", file=sys.stderr)
        sys.exit(1)
    end_idx = m.end()

    new_src = src[:start_idx] + new_middle + "\n\n" + src[end_idx:]

    # Update api_check to also allow query-submodule-derived fields.
    old_check = '''local function api_check(v, path)
  if v.list == "allusers" and not referer_allows_allusers() then
    return false, path .. ": list=allusers requires a same-origin Referer from an authorized admin page"
  end

  local action_fields = v.action and mw_api_actions[v.action]
  if action_fields then
    for key in pairs(v) do
      if api_common[key] == nil and action_fields[key] == nil then
        return false, path .. "." .. key .. ": not a valid parameter for action=" .. v.action
      end
    end
  end

  return true
end'''
    new_check = '''local function api_check(v, path)
  if v.list == "allusers" and not referer_allows_allusers() then
    return false, path .. ": list=allusers requires a same-origin Referer from an authorized admin page"
  end

  local action_fields = v.action and mw_api_actions[v.action]
  if action_fields then
    local extra_fields = action_fields
    if v.action == "query" then
      extra_fields = merge(action_fields, resolve_query_submodule_fields(v))
    end
    for key in pairs(v) do
      -- api_legacy_fields stays globally allowed even for precisely-modeled
      -- actions: it includes MediaWiki's shared page-set resolution fields
      -- (titles, pageids, generator, redirects, ...) used across many
      -- action=query submodules, which aren't part of any one submodule's
      -- own getAllowedParams() and so aren't captured per-action above.
      if api_common[key] == nil and api_legacy_fields[key] == nil and extra_fields[key] == nil then
        return false, path .. "." .. key .. ": not a valid parameter for action=" .. v.action
      end
    end
  end

  return true
end'''
    if old_check in new_src:
        new_src = new_src.replace(old_check, new_check)
    elif new_check not in new_src:
        print("ERROR: could not find api_check block to update", file=sys.stderr)
        sys.exit(1)
    # else: already applied by a previous run (idempotent re-run) - no-op.

    # api_schema's T.object() needs the query-submodule fields in its base
    # superset too (api_check only narrows down from what T.object already permits).
    old_schema = '''local api_schema = T.with_check(
  T.object(merge(api_common, api_legacy_fields, mw_api_action_fields_union)),
  api_check
)'''
    new_schema = '''local api_schema = T.with_check(
  T.object(merge(api_common, api_legacy_fields, mw_api_action_fields_union, mw_query_submodule_fields_union)),
  api_check
)'''
    if old_schema in new_src:
        new_src = new_src.replace(old_schema, new_schema)
    elif new_schema not in new_src:
        print("ERROR: could not find api_schema block to update", file=sys.stderr)
        sys.exit(1)
    # else: already applied by a previous run (idempotent re-run) - no-op.

    open(LUA_PATH, "w", encoding="utf-8").write(new_src)
    print(f"Integrated {len(action_keys)} Tier 2/5 actions + "
          f"{len(prop_keys)} prop + {len(list_keys)} list + {len(meta_keys)} meta submodules.")
    print(f"Wrote {LUA_PATH}")

if __name__ == "__main__":
    main()

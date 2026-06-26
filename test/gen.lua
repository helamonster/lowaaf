-- test/gen.lua
-- Generates valid and invalid test values by walking the T._registry metadata
-- that types.lua attaches to every validator function.
--
-- gen.valid_value(validator)    → Lua value that should pass, or nil if unknown
-- gen.invalid_values(validator) → array of { value, label } that should fail
--
-- Both functions verify their output against the real validator before returning,
-- so callers get confirmed-good / confirmed-bad values with no extra logic.

local cjson = require "cjson.safe"
local gen = {}

-- ── Upvalues set at the bottom of this file after waf.types loads ─────────────

local REG   -- T._registry: maps validator function → meta table
local T_uuid_re
local T_fileid_re

-- ── Helpers ───────────────────────────────────────────────────────────────────

local function copy(t)
  local r = {}
  for k, v in pairs(t) do r[k] = v end
  return r
end

local function set_ctx()
  ngx.ctx = { waf_verbose = 0, waf_log_mode = false }
end

-- ── JWT test helpers ──────────────────────────────────────────────────────────

local function b64url(s)
  return ngx.encode_base64(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
end

-- Returns a synthetic unsigned JWT string from two plain-Lua tables.
local function make_jwt(claims_obj, header_obj)
  local hdr = header_obj or { alg = "RS256", typ = "JWT" }
  local claims_json = cjson.encode(claims_obj)
  local header_json = cjson.encode(hdr)
  if not claims_json or not header_json then return nil end
  return b64url(header_json) .. "." .. b64url(claims_json) .. ".fakesig"
end

-- ── Raw valid value (unverified) ──────────────────────────────────────────────

local function raw_valid(meta)
  if not meta then return nil end
  local t = meta.type
  local opts = meta.opts or {}

  if t == "string" then
    if opts.enum then
      for k in pairs(opts.enum) do return k end
    end
    local min = opts.min or 1
    -- For match patterns we can't reverse, return the minimum-length string
    -- and let the caller's verify step reject it if the pattern isn't satisfied.
    return string.rep("a", min)

  elseif t == "number" then
    local v = opts.min or 0
    if opts.integer then return math.floor(v) end
    return v

  elseif t == "boolean"       then return false
  elseif t == "uuid"          then return "00000000-0000-4000-8000-000000000000"
  elseif t == "email"         then return "test@test.com"
  elseif t == "iso8601"       then return "2024-01-01T00:00:00Z"
  elseif t == "semver"        then return "1.0.0"
  elseif t == "url"           then return "https://example.com"
  elseif t == "base64"        then return "dGVzdA=="   -- "test"
  elseif t == "lang_tag"      then return "en"
  elseif t == "bearer_token"  then return "Bearer testtoken"
  elseif t == "sec_gpc"       then return "1"
  elseif t == "http_priority" then return "u=3"
  elseif t == "bool_query"    then return "true"
  elseif t == "any"           then return "x"
  elseif t == "dict"  then return {}
  elseif t == "jwt"   then return nil   -- opaque; can't auto-gen

  elseif t == "jwt_claims" then
    local claims_meta = meta.claims_validator and REG[meta.claims_validator]
    local header_meta = meta.header_validator and REG[meta.header_validator]
    local claims_obj = (claims_meta and raw_valid(claims_meta)) or {}
    local header_obj = (header_meta and raw_valid(header_meta))
    -- If the schema declares exp, set it to an hour from now so the exp check passes.
    if claims_obj.exp ~= nil then claims_obj.exp = ngx.time() + 3600 end
    return make_jwt(claims_obj, header_obj)

  elseif t == "bearer_jwt" then
    local claims_meta = meta.claims_validator and REG[meta.claims_validator]
    local header_meta = meta.header_validator and REG[meta.header_validator]
    local claims_obj = (claims_meta and raw_valid(claims_meta)) or {}
    local header_obj = (header_meta and raw_valid(header_meta))
    if claims_obj.exp ~= nil then claims_obj.exp = ngx.time() + 3600 end
    local jwt = make_jwt(claims_obj, header_obj)
    return jwt and ("Bearer " .. jwt) or nil

  elseif t == "nullable" then
    -- Prefer a concrete inner value so cross-field consistency rules (e.g.
    -- cipher type/sub-object check) receive a fully-populated body.
    local inner_meta = meta.inner and REG[meta.inner]
    if inner_meta then return raw_valid(inner_meta) end
    return nil

  elseif t == "with_check" then
    return meta.base_meta and raw_valid(meta.base_meta) or nil

  elseif t == "array" then
    if opts.min and opts.min > 0 then
      local inner_meta = meta.inner and REG[meta.inner]
      if not inner_meta then return nil end
      local elem = raw_valid(inner_meta)
      if elem == nil then return nil end
      local arr = {}
      for i = 1, opts.min do arr[i] = elem end
      return arr
    end
    return {}

  elseif t == "object" then
    local obj = {}
    for key, sub_v in pairs(meta.schema) do
      if type(sub_v) == "function" and REG[sub_v] then
        local v = raw_valid(REG[sub_v])
        if v ~= nil then obj[key] = v end
      end
    end
    return obj
  end

  return nil
end

-- ── Public: valid_value ───────────────────────────────────────────────────────

function gen.valid_value(validator)
  if type(validator) ~= "function" then return nil end
  local meta = REG[validator]
  if not meta then return nil end
  local v = raw_valid(meta)
  if v == nil then return nil end
  set_ctx()
  local ok = validator(v, "$")
  if not ok then return nil end
  return v
end

-- ── Raw invalid candidates (unverified) ──────────────────────────────────────

local function raw_invalids(meta)
  local t = meta.type
  local opts = meta.opts or {}
  local results = {}
  local function add(value, label) results[#results+1] = { value=value, label=label } end

  if t == "string" then
    add(123,   "number instead of string")
    add(false, "boolean instead of string")
    if opts.max then
      add(string.rep("x", opts.max + 1),
          "length " .. opts.max+1 .. " (max " .. opts.max .. ")")
    end
    if opts.min and opts.min > 0 then
      local short = opts.min > 1 and string.rep("x", opts.min - 1) or ""
      add(short, "length " .. math.max(0, opts.min-1) .. " (min " .. opts.min .. ")")
    end
    if opts.enum then
      add("__invalid_enum__", "value not in enum")
      for k in pairs(opts.enum) do
        local upper = k:upper()
        if upper ~= k then add(upper, "wrong-case enum value '" .. upper .. "'") end
        break
      end
    end
    if opts.match and not opts.enum then
      add("!@#$%^&*()", "string failing match pattern")
    end
    add("\0",       "null byte")
    add("a\r\nb",   "CRLF injection")
    add("a\x1bb",   "ESC char")

  elseif t == "number" then
    add("notanumber", "string instead of number")
    add(false, "boolean instead of number")
    if opts.max then
      add(opts.max + 1, "value " .. opts.max+1 .. " (max+1)")
    end
    if opts.min then
      add(opts.min - 1, "value " .. opts.min-1 .. " (min-1)")
    end
    if opts.integer then
      local base = opts.min or 0
      add(base + 0.5, "float " .. base+0.5 .. " (integer required)")
    end

  elseif t == "boolean" then
    add("true",  "string 'true' instead of boolean")
    add(1,       "integer 1 instead of boolean")

  elseif t == "uuid" then
    add("not-a-uuid",                               "invalid UUID format")
    add("00000000-0000-0000-0000-00000000000z",     "invalid UUID hex char")
    add("",                                         "empty string instead of UUID")
    add(123,                                        "number instead of UUID")
    add("00000000-0000-0000-0000-000000000000",     "UUID version 0 (invalid)")

  elseif t == "email" then
    add("notanemail",                               "no @ sign")
    add("@nodomain.com",                            "no local part")
    add("user@",                                    "no domain")
    add("",                                         "empty string")
    add(123,                                        "number instead of email")
    add(string.rep("a", 315) .. "@x.com",          "email > 320 chars")

  elseif t == "iso8601" then
    add("not-a-date",           "non-date string")
    add("2024-01-01",           "date without time")
    add("2024-01-01T00:00:00",  "missing Z suffix")
    add(123,                    "number instead of date")

  elseif t == "nullable" then
    local inner_meta = meta.inner and REG[meta.inner]
    if inner_meta then
      for _, pair in ipairs(raw_invalids(inner_meta)) do
        add(pair.value, "nullable inner: " .. pair.label)
      end
    end

  elseif t == "array" then
    add("notanarray", "string instead of array")
    add({key="val"}, "object instead of array")
    local inner_meta = meta.inner and REG[meta.inner]
    if opts.max then
      local elem = inner_meta and raw_valid(inner_meta) or "x"
      if elem ~= nil then
        local arr = {}
        for i = 1, opts.max + 1 do arr[i] = elem end
        add(arr, "length " .. opts.max+1 .. " (max+1)")
      end
    end
    if opts.min and opts.min > 0 then
      add({}, "empty array (min " .. opts.min .. ")")
    end
    if inner_meta then
      local elem_invalids = raw_invalids(inner_meta)
      if #elem_invalids > 0 then
        add({ elem_invalids[1].value }, "invalid element[1]: " .. elem_invalids[1].label)
      end
    end

  elseif t == "object" then
    local base = raw_valid(meta) or {}
    add("notanobject", "string instead of object")
    local with_extra = copy(base)
    with_extra["__waf_unknown_key__"] = "x"
    add(with_extra, "unknown key '__waf_unknown_key__'")
    if opts.required then
      for key in pairs(opts.required) do
        local without = copy(base)
        without[key] = nil
        add(without, "missing required field '" .. key .. "'")
      end
    end
    for key, sub_v in pairs(meta.schema) do
      local sub_meta = type(sub_v) == "function" and REG[sub_v]
      if sub_meta then
        for _, pair in ipairs(raw_invalids(sub_meta)) do
          if pair.value ~= nil then
            local mutated = copy(base)
            mutated[key] = pair.value
            add(mutated, "." .. key .. ": " .. pair.label)
          end
        end
      end
    end

  elseif t == "dict" then
    add("notadict", "string instead of object")
    add(123,        "number instead of object")

  elseif t == "with_check" then
    if meta.base_meta then
      for _, pair in ipairs(raw_invalids(meta.base_meta)) do
        add(pair.value, pair.label)
      end
    end
    for _, hint in ipairs(meta.invalid_hints or {}) do
      add(hint.value, hint.label)
    end

  elseif t == "jwt" then
    add("not.a.jwt",  "invalid JWT (bad chars)")
    add("a.b",        "JWT with only two segments")
    add("",           "empty string")
    add(123,          "number instead of JWT")

  elseif t == "jwt_claims" then
    add("not.a.jwt",  "invalid JWT (bad chars)")
    add("a.b",        "JWT with only two segments")
    add("",           "empty string")
    add(123,          "number instead of JWT")
    local expired = make_jwt({ exp = ngx.time() - 3600 })
    if expired then add(expired, "expired JWT (exp one hour ago)") end

  elseif t == "bearer_jwt" then
    add("notabearer",    "missing 'Bearer ' prefix")
    add("bearer token",  "lowercase 'bearer' prefix")
    add("",              "empty string")
    add(123,             "number instead of string")
    local expired_jwt = make_jwt({ exp = ngx.time() - 3600 })
    if expired_jwt then add("Bearer " .. expired_jwt, "Bearer with expired JWT") end

  elseif t == "base64" then
    add("not!valid==", "invalid base64 characters")
    add(123,           "number instead of base64")
    if opts.max then
      add(string.rep("a", opts.max + 1), "length " .. opts.max+1 .. " (max+1)")
    end

  elseif t == "semver" then
    add("1.0",     "missing patch version")
    add("notver",  "non-semver string")

  elseif t == "url" then
    add("not-a-url",         "missing protocol")
    add("ftp://example.com", "non-http/https scheme")

  elseif t == "bearer_token" then
    add("nobearer",   "missing 'Bearer ' prefix")
    add("Bearer",     "no token value after 'Bearer'")

  elseif t == "sec_gpc" then
    add("0", "value '0' (only '1' valid)")
    add("2", "value '2' out of range")

  elseif t == "http_priority" then
    add("u=8",    "urgency 8 (max is 7)")
    add("invalid","non-priority string")

  elseif t == "lang_tag" then
    add("a",                      "single char (min 2)")
    add(string.rep("a", 36),      "too long (max 35)")

  elseif t == "bool_query" then
    add("yes", "value 'yes' (only true/false valid)")
    add("1",   "value '1'")

  -- T.any: nothing is invalid
  end

  return results
end

-- ── Public: invalid_values ────────────────────────────────────────────────────

function gen.invalid_values(validator)
  if type(validator) ~= "function" then return {} end
  local meta = REG[validator]
  if not meta then return {} end
  local candidates = raw_invalids(meta)
  local confirmed = {}
  for _, pair in ipairs(candidates) do
    set_ctx()
    local ok = validator(pair.value, "$")
    if not ok then confirmed[#confirmed+1] = pair end
  end
  return confirmed
end

-- ── Path extraction ───────────────────────────────────────────────────────────

-- Sample concrete values for path-pattern placeholders.
local PATH_UUID   = "00000000-0000-4000-8000-000000000000"
local PATH_FILEID = "aGVsbG8x"   -- base64url "hello1"

-- Literal (non-pattern) string substitution using string.find plain mode.
local function plain_sub(str, from, to)
  if from == "" then return str end
  local result = {}
  local pos = 1
  local from_len = #from
  while true do
    local s = str:find(from, pos, true)
    if not s then
      result[#result+1] = str:sub(pos)
      break
    end
    result[#result+1] = str:sub(pos, s - 1)
    result[#result+1] = to
    pos = s + from_len
  end
  return table.concat(result)
end

-- Convert a route path regex to a concrete URI suitable for testing.
function gen.path_from_pattern(pat)
  local p = pat
  if p:sub(1,1) == "^" then p = p:sub(2) end
  if p:sub(-1)  == "$" then p = p:sub(1,-2) end
  -- Unescape regex `\.` → `.`  (PCRE escaped dot; literal in a URI)
  p = p:gsub("\\%.", ".")
  -- Substitute known regex fragments with concrete literals (plain-text find)
  if T_uuid_re   then p = plain_sub(p, T_uuid_re,   PATH_UUID)   end
  if T_fileid_re then p = plain_sub(p, T_fileid_re, PATH_FILEID) end
  -- Common remaining patterns (Lua pattern substitution on what's left):
  p = p:gsub("%[%^/%]%{[^}]*%}", "testval") -- [^/]{n,m}
  p = p:gsub("%[%^/%]%+",        "testval") -- [^/]+
  p = p:gsub("%[%^/%]%*",        "")        -- [^/]*
  p = p:gsub("%.%+",             "testval") -- .+
  p = p:gsub("%[0%-9%]%{1,3%}",  "0")       -- [0-9]{1,3}
  p = p:gsub("%[0%-9%]%{1,2%}",  "0")       -- [0-9]{1,2}
  p = p:gsub("%(/%|%$%)", "/")           -- (/|$) → /
  p = p:gsub("%(%.%a+%)%?", "")          -- (.js)? etc.
  p = p:gsub("[%(%)%|%?]", "")           -- stray alternation chars
  p = p:gsub("%{[^}]*%}", "")            -- remaining {n} quantifiers
  return p
end

function gen.route_uri(route)
  local pats = route.paths or route.path
  if type(pats) == "table" then pats = pats[1] end
  return gen.path_from_pattern(pats)
end

-- ── Load waf.types and wire up upvalues ───────────────────────────────────────

local T = require "waf.types"
REG        = T._registry
T_uuid_re  = T.uuid_re
T_fileid_re = T.fileid_re

return gen

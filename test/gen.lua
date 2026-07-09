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

-- Stable (sorted-key) string representation for dedup in gen.valid_values.
-- Not valid JSON — just a deterministic key for the seen-set.
local function stable_enc(v)
  if v == nil            then return "\0nil"        end
  if v == ngx.null       then return "\0null"       end
  if type(v) ~= "table"  then return tostring(v)   end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = tostring(k) end
  table.sort(keys)
  local parts = {}
  for _, k in ipairs(keys) do
    parts[#parts + 1] = k .. "=" .. stable_enc(v[k])
  end
  return "{" .. table.concat(parts, ",") .. "}"
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

  elseif t == "number_query" then
    local v = opts.min or 0
    if opts.integer then v = math.floor(v) end
    return tostring(v)

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
  elseif t == "dict"          then return {}
  elseif t == "uuid_or_empty" then return ""
  elseif t == "jwt"           then return nil   -- opaque; can't auto-gen

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
    -- Verify the candidate passes the inner validator before returning it;
    -- match-pattern fields produce a candidate that fails their own pattern,
    -- in which case nil (field absent) is the correct fallback for a nullable.
    local inner_meta = meta.inner and REG[meta.inner]
    if inner_meta and meta.inner then
      local v = raw_valid(inner_meta)
      if v ~= nil then
        set_ctx()
        if meta.inner(v, "$") then return v end
      end
    end
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

-- ── Raw valid value candidates (unverified, multiple per type) ───────────────
-- Parallel to raw_valid but returns an array of { value, label } pairs so that
-- callers can test the full breadth of the valid surface (enum exhaustion,
-- boolean true+false, number min+max, nullable absent vs. set).

local function raw_valids(meta)
  if not meta then return {} end
  local t    = meta.type
  local opts = meta.opts or {}
  local results = {}
  local function add(value, label)
    results[#results + 1] = { value = value, label = label }
  end

  if t == "string" then
    if opts.enum then
      for k in pairs(opts.enum) do add(k, "'" .. k .. "'") end
    else
      -- Six-point boundary: min, min+1, max-1, max.
      -- match-pattern strings will produce values that fail the pattern and
      -- are filtered by gen.valid_values — that is expected and fine.
      local min = opts.min or 1
      add(string.rep("a", min),     "length " .. min       .. " (min)")
      add(string.rep("a", min + 1), "length " .. (min + 1) .. " (min+1)")
      if opts.max then
        add(string.rep("a", opts.max - 1), "length " .. (opts.max - 1) .. " (max-1)")
        add(string.rep("a", opts.max),     "length " .. opts.max       .. " (max)")
      end
    end

  elseif t == "number" or t == "number_query" then
    -- Six-point boundary: min, min+1, max-1, max.
    -- stable_enc dedup in gen.valid_values collapses identical values
    -- (e.g. reprompt min=0 max=1: min+1==max and max-1==min).
    local wrap = (t == "number_query") and tostring or function(x) return x end
    local lo = opts.min or 0
    if opts.integer then lo = math.floor(lo) end
    add(wrap(lo),     "min(" .. lo .. ")")
    add(wrap(lo + 1), "min+1(" .. (lo + 1) .. ")")
    if opts.max then
      local hi = opts.max
      if opts.integer then hi = math.floor(hi) end
      add(wrap(hi - 1), "max-1(" .. (hi - 1) .. ")")
      add(wrap(hi),     "max(" .. hi .. ")")
    end

  elseif t == "boolean" then
    add(true,  "true")
    add(false, "false")

  elseif t == "bool_query" then
    add("true",  "'true'")
    add("false", "'false'")
    add("",      "''")

  elseif t == "nullable" then
    add(nil, "absent")
    local inner_meta = meta.inner and REG[meta.inner]
    if inner_meta and meta.inner then
      -- For complex inner types (object/array/dict/with_check), produce one
      -- "set" variant rather than recursing into field-level variants.
      local inner_t = inner_meta.type
      local is_complex = (inner_t == "object" or inner_t == "with_check"
                          or inner_t == "array" or inner_t == "dict")
      local inner_pairs
      if is_complex then
        local v = raw_valid(inner_meta)
        if v ~= nil then inner_pairs = { { value = v, label = "set" } } end
      else
        inner_pairs = raw_valids(inner_meta)
      end
      if inner_pairs then
        for _, pair in ipairs(inner_pairs) do
          if pair.value ~= nil then
            set_ctx()
            if meta.inner(pair.value, "$") then add(pair.value, pair.label) end
          end
        end
      end
    end

  elseif t == "object" or t == "with_check" then
    local schema_meta = (t == "with_check") and meta.base_meta or meta
    if not schema_meta then return results end
    local base = raw_valid(schema_meta) or {}
    add(base, "base")
    for key, sub_v in pairs(schema_meta.schema or {}) do
      local sub_meta = type(sub_v) == "function" and REG[sub_v]
      if sub_meta then
        local field_pairs = raw_valids(sub_meta)
        if #field_pairs > 1 then
          for _, pair in ipairs(field_pairs) do
            local variant    = copy(base)
            variant[key]     = pair.value   -- nil removes the key
            add(variant, "." .. key .. "=" .. pair.label)
          end
        end
      end
    end
    -- Explicit valid hints: coordinated multi-field variants (with_check only)
    -- that single-field substitution cannot produce.
    for _, hint in ipairs(meta.valid_hints or {}) do
      add(hint.value, hint.label)
    end

  else
    local v = raw_valid(meta)
    if v ~= nil then add(v, "base") end
  end

  return results
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

-- ── Public: valid_values ─────────────────────────────────────────────────────
-- Returns all confirmed-valid variants for the validator: the base value plus
-- alternatives covering enums, boolean true/false, number min/max, nullable
-- absent/set, and per-field substitutions in objects.
-- Deduplicates by cjson encoding so identical bodies are tested only once.

function gen.valid_values(validator)
  if type(validator) ~= "function" then return {} end
  local meta = REG[validator]
  if not meta then return {} end
  local candidates = raw_valids(meta)
  local confirmed  = {}
  local seen       = {}
  for _, pair in ipairs(candidates) do
    local enc = stable_enc(pair.value)
    if not seen[enc] then
      seen[enc] = true
      set_ctx()
      local ok = validator(pair.value, "$")
      if ok then confirmed[#confirmed + 1] = pair end
    end
  end
  return confirmed
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

  elseif t == "number_query" then
    add("notanumber", "string instead of number")
    add(false, "boolean instead of a numeric string")
    if opts.max then
      add(tostring(opts.max + 1), "value " .. opts.max+1 .. " (max+1)")
    end
    if opts.min then
      add(tostring(opts.min - 1), "value " .. opts.min-1 .. " (min-1)")
    end
    if opts.integer then
      local base = opts.min or 0
      add(tostring(base + 0.5), "float " .. base+0.5 .. " (integer required)")
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

  elseif t == "uuid_or_empty" then
    -- empty string and nil/ngx.null are VALID for this type; only test non-empty non-UUIDs
    add("not-a-uuid",                               "invalid UUID format (non-empty)")
    add("00000000-0000-0000-0000-000000000000",     "UUID version 0 (invalid)")
    add(123,                                        "number instead of UUID/empty")
    add(false,                                      "boolean instead of UUID/empty")
    add("\0",                                       "null byte")

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
    local inner_meta = meta.inner and REG[meta.inner]
    if inner_meta then
      local elem_invalids = raw_invalids(inner_meta)
      if #elem_invalids > 0 then
        add({ testkey = elem_invalids[1].value },
            "invalid dict value: " .. elem_invalids[1].label)
      end
    end

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
    add(false,         "boolean instead of base64")
    if opts.max then
      add(string.rep("a", opts.max + 1), "length " .. opts.max+1 .. " (max+1)")
    end

  elseif t == "semver" then
    add("1.0",                   "missing patch version")
    add("notver",                "non-semver string")
    add(123,                     "number instead of semver")
    add(false,                   "boolean instead of semver")
    add(string.rep("x", 129),   "length 129 (max 128)")
    add("1.0.0\0",               "null byte")
    add("1.0.0\r\n",             "CRLF injection")

  elseif t == "url" then
    add("not-a-url",                                     "missing protocol")
    add("ftp://example.com",                             "non-http/https scheme")
    add(123,                                             "number instead of URL")
    add(false,                                           "boolean instead of URL")
    add("https://example.com/" .. string.rep("a", 2028), "length 2049 (max 2048)")
    add("https://example.com/\0",                        "null byte in URL")
    add("https://example.com/a\r\nb",                    "CRLF injection")

  elseif t == "bearer_token" then
    add("nobearer",                          "missing 'Bearer ' prefix")
    add("Bearer",                            "no token value after 'Bearer'")
    add(123,                                 "number instead of token")
    add(false,                               "boolean instead of token")
    add("Bearer " .. string.rep("a", 2042), "length 2049 (max 2048)")
    add("Bearer tok\0en",                   "null byte")

  elseif t == "sec_gpc" then
    add("0",   "value '0' (only '1' valid)")
    add("2",   "value '2' out of range")
    add(123,   "number instead of string")
    add(false, "boolean instead of string")

  elseif t == "http_priority" then
    add("u=8",    "urgency 8 (max is 7)")
    add("invalid","non-priority string")
    add(123,      "number instead of string")
    add(false,    "boolean instead of string")

  elseif t == "lang_tag" then
    add("a",                   "single char (min 2)")
    add(string.rep("a", 36),   "too long (max 35)")
    add(123,                   "number instead of language tag")
    add(false,                 "boolean instead of language tag")
    add("en_US",               "underscore instead of hyphen")
    add("en-",                 "trailing hyphen (empty subtag)")
    add("en\0",                "null byte")

  elseif t == "bool_query" then
    add("yes",  "value 'yes' (only true/false valid)")
    add("1",    "value '1'")
    add(123,    "number instead of string")
    add(false,  "boolean instead of string")

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
  -- Strip a leading PCRE inline-modifier group, e.g. "(?i)" - it's not an
  -- alternation group (that generic resolver would otherwise mangle it into
  -- a bare "i"), it just makes the whole pattern case-insensitive.
  p = p:gsub("^%(%?[a-zA-Z]+%)", "")
  if p:sub(1,1) == "^" then p = p:sub(2) end
  if p:sub(-1)  == "$" then p = p:sub(1,-2) end
  -- Unescape regex `\.` → `.`  (PCRE escaped dot; literal in a URI)
  p = p:gsub("\\%.", ".")
  -- Substitute known regex fragments with concrete literals (plain-text find)
  if T_uuid_re   then p = plain_sub(p, T_uuid_re,   PATH_UUID)   end
  if T_fileid_re then p = plain_sub(p, T_fileid_re, PATH_FILEID) end
  -- Resolve any other quantified character class (e.g. a bare hex-32 id
  -- pattern like `[0-9a-fA-F]{32}`) into a concrete string of the required
  -- length, using a representative character from the class. Negated
  -- classes (`[^/]{n,m}` etc.) are left for the specific rules below.
  p = p:gsub("%[([^%]]-)%]%{(%d+)[^}]-%}", function(class, n)
    if class:sub(1, 1) == "^" then return nil end
    local ch = class:match("%d") or class:match("%a") or class:sub(1, 1)
    return ch:rep(tonumber(n))
  end)
  -- Common remaining patterns (Lua pattern substitution on what's left):
  p = p:gsub("%[%^/%]%{[^}]*%}", "testval") -- [^/]{n,m}
  p = p:gsub("%[%^/%]%+",        "testval") -- [^/]+
  p = p:gsub("%[%^/%]%*",        "")        -- [^/]*
  p = p:gsub("%.%+",             "testval") -- .+
  -- Resolve any remaining one-or-more character class (e.g. `[0-9.]+`,
  -- `[0-9A-Za-z_.-]+`) into a single representative character.
  p = p:gsub("%[([^%]]-)%]%+", function(class)
    if class:sub(1, 1) == "^" then return nil end
    return class:match("%d") or class:match("%a") or class:sub(1, 1)
  end)
  p = p:gsub("%[0%-9%]%{1,3%}",  "0")       -- [0-9]{1,3}
  p = p:gsub("%[0%-9%]%{1,2%}",  "0")       -- [0-9]{1,2}
  -- Resolve alternation groups `(?:a|b|c)` / `(a|b|c)` to their first
  -- alternative so the result is a concrete, matchable path. This also
  -- covers non-alternating optional groups like `(\.js)?`, which reduce
  -- to their single (only) branch.
  p = p:gsub("%(%??:?([^%(%)]-)%)%??", function(inner)
    return inner:match("^[^|]*")
  end)
  p = p:gsub("[%(%)%|%?]", "")           -- stray alternation chars (fallback)
  p = p:gsub("%{[^}]*%}", "")            -- remaining {n} quantifiers (fallback)
  return p
end

function gen.route_uri(route)
  if route._test_uri then return route._test_uri end
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

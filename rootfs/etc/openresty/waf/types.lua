-- --------------------------------------------------------------------------------------
-- 
-- Lua OpenResty Web Application and API Firewall (LOWAAF)
--
-- Concept, Framework and Application Firewall Implementation by:
-- Jeremy Bryan Smith <helamonster@gmail.com>
-- <https://jeremybryansmith.com>
--
-- With assistance from: Claude Sonnet 4.6 <noreply@anthropic.com> 
--
-- --------------------------------------------------------------------------------------
--
-- types.lua : Validator Factory Library : Building blocks for declaring request schemas
--
-- --------------------------------------------------------------------------------------


local ngx   = ngx
local cjson = require "cjson.safe"
local T = {}
T._registry = setmetatable({}, { __mode = "k" })  -- maps validator fn → meta table

-- base64url → standard base64, then decode (JWT uses base64url with no padding)
local function b64url_decode(s)
  s = s:gsub("%-", "+"):gsub("_", "/")
  local pad = #s % 4
  if pad == 2 then s = s .. "=="
  elseif pad == 3 then s = s .. "="
  end
  return ngx.decode_base64(s)
end

local function fail(msg)
  return false, msg
end

-- Compact human-readable representation of a value for deny log messages.
-- Strings are truncated at 64 chars (encrypted blobs are very long).
local function val_str(v)
  local t = type(v)
  if t == "string" then
    if #v > 64 then return "'" .. v:sub(1, 64) .. "...'" end
    return "'" .. v .. "'"
  elseif t == "number" or t == "boolean" then
    return tostring(v)
  elseif t == "table" then
    local n = #v
    return n > 0 and ("[array(" .. n .. ")]") or "[object]"
  end
  return tostring(v)
end

-- Validators read ngx.ctx.waf_verbose (set once by core.run) to decide
-- whether to include the failing value in the error message (verbose >= 2).

function T.string(opts)
  opts = opts or {}
  local fn = function(v, path)
    local verbose = ngx.ctx.waf_verbose or 0
    if type(v) ~= "string" then
      local msg = path .. " must be a string"
      if verbose >= 2 then msg = msg .. " (got: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.min and #v < opts.min then
      local msg = path .. " too short (min " .. opts.min .. ")"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.max and #v > opts.max then
      local msg = path .. " too long (max " .. opts.max .. ")"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.match and not ngx.re.find(v, opts.match, "jo") then
      local msg = path .. " invalid format"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.not_match and ngx.re.find(v, opts.not_match, "jo") then
      local msg = path .. " contains forbidden characters"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.enum and not opts.enum[v] then
      local msg = path .. " invalid value"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    return true
  end
  T._registry[fn] = { type = "string", opts = opts }
  return fn
end

function T.number(opts)
  opts = opts or {}
  local fn = function(v, path)
    local verbose = ngx.ctx.waf_verbose or 0
    if type(v) ~= "number" then
      local msg = path .. " must be a number"
      if verbose >= 2 then msg = msg .. " (got: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.integer and v % 1 ~= 0 then
      local msg = path .. " must be an integer"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.min and v < opts.min then
      local msg = path .. " too small (min " .. opts.min .. ")"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    if opts.max and v > opts.max then
      local msg = path .. " too large (max " .. opts.max .. ")"
      if verbose >= 2 then msg = msg .. " (value: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    return true
  end
  T._registry[fn] = { type = "number", opts = opts }
  return fn
end

function T.boolean()
  local fn = function(v, path)
    local verbose = ngx.ctx.waf_verbose or 0
    if type(v) ~= "boolean" then
      local msg = path .. " must be a boolean"
      if verbose >= 2 then msg = msg .. " (got: " .. val_str(v) .. ")" end
      return fail(msg)
    end
    return true
  end
  T._registry[fn] = { type = "boolean" }
  return fn
end

function T.uuid()
  local fn = T.string({
    match = [[^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$]]
  })
  T._registry[fn] = { type = "uuid" }
  return fn
end

function T.email()
  local fn = T.string({
    min       = 3,
    max       = 320,
    match     = [[^[^@\s]+@[^@\s]+\.[^@\s]+$]],
    not_match = "[\\x00-\\x1f\\x7f<>\"]",
  })
  T._registry[fn] = { type = "email" }
  return fn
end

-- passes if value is JSON null or Lua nil, otherwise delegates to inner
function T.nullable(inner)
  local fn = function(v, path)
    if v == ngx.null or v == nil then return true end
    return inner(v, path)
  end
  T._registry[fn] = { type = "nullable", inner = inner }
  return fn
end

function T.array(inner, opts)
  opts = opts or {}
  local fn = function(v, path)
    if type(v) ~= "table" then return fail(path .. " must be an array") end
    local n = #v
    if opts.min and n < opts.min then
      return fail(path .. " array too short (min " .. opts.min .. ")")
    end
    if opts.max and n > opts.max then
      return fail(path .. " array too long (max " .. opts.max .. ")")
    end
    local log_mode = ngx.ctx.waf_log_mode
    local errors = log_mode and {}
    for i = 1, n do
      local ok, err = inner(v[i], path .. "[" .. i .. "]")
      if not ok then
        if log_mode then errors[#errors + 1] = err
        else return false, err end
      end
    end
    if log_mode and errors and #errors > 0 then
      return false, table.concat(errors, "\n")
    end
    return true
  end
  T._registry[fn] = { type = "array", inner = inner, opts = opts }
  return fn
end

-- Validates a table with arbitrary string keys, all mapped to the same value type.
-- Use when keys are dynamic (e.g. IDs) and only the value shape is known.
function T.dict(value_validator)
  local fn = function(v, path)
    if type(v) ~= "table" then return fail(path .. " must be an object") end
    local log_mode = ngx.ctx.waf_log_mode
    local errors = log_mode and {}
    for key, val in pairs(v) do
      local ok, err = value_validator(val, path .. "." .. tostring(key))
      if not ok then
        if log_mode then errors[#errors + 1] = err
        else return false, err end
      end
    end
    if log_mode and errors and #errors > 0 then
      return false, table.concat(errors, "\n")
    end
    return true
  end
  T._registry[fn] = { type = "dict", inner = value_validator }
  return fn
end

-- schema: { key = validator, ... }
-- opts.required: { key = true, ... } for mandatory keys
-- unknown keys are always rejected
-- All violations are collected and returned as a newline-joined string so that
-- callers (check_body, check_query) can log each one separately via deny().
function T.object(schema, opts)
  opts = opts or {}
  local fn = function(v, path)
    local verbose = ngx.ctx.waf_verbose or 0
    if type(v) ~= "table" then return fail(path .. " must be an object") end
    local log_mode = ngx.ctx.waf_log_mode
    local errors = log_mode and {}
    for key, _ in pairs(v) do
      if not schema[key] then
        local msg = path .. "." .. tostring(key) .. " is not an allowed key"
        if verbose >= 2 then msg = msg .. " (value: " .. val_str(v[key]) .. ")" end
        if log_mode then errors[#errors + 1] = msg
        else return fail(msg) end
      end
    end
    for key, validator in pairs(schema) do
      local value = v[key]
      if value ~= nil then
        local ok, err = validator(value, path .. "." .. key)
        if not ok then
          if log_mode then errors[#errors + 1] = err
          else return false, err end
        end
      elseif opts.required and opts.required[key] then
        local msg = path .. "." .. key .. " is required"
        if log_mode then errors[#errors + 1] = msg
        else return fail(msg) end
      end
    end
    if log_mode and #errors > 0 then return false, table.concat(errors, "\n") end
    return true
  end
  T._registry[fn] = { type = "object", schema = schema, opts = opts }
  return fn
end

-- ---------------------------------------------------------------------------
-- Common format validators
-- ---------------------------------------------------------------------------

-- Semantic version (semver.org): MAJOR.MINOR.PATCH[-prerelease][+build]
function T.semver()
  local fn = T.string({
    max   = 128,
    match = [[^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$]],
  })
  T._registry[fn] = { type = "semver" }
  return fn
end

-- HTTP or HTTPS URL (RFC 3986 character set)
-- unreserved: A-Za-z0-9 - . _ ~
-- gen-delims: : / ? # [ ] @
-- sub-delims: ! $ & ' ( ) * + , ; =
-- percent-encoding: %
function T.url()
  local fn = T.string({
    max   = 2048,
    match = [[^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$]],
  })
  T._registry[fn] = { type = "url" }
  return fn
end

-- JSON Web Token (RFC 7519): three base64url segments separated by dots.
-- Use T.jwt_claims(schema) instead when you want to validate payload contents.
function T.jwt()
  local fn = T.string({
    max   = 8192,
    match = [[^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$]],
  })
  T._registry[fn] = { type = "jwt" }
  return fn
end

-- Like T.jwt() but also decodes and validates the header and/or payload.
-- T.jwt_claims(claims_schema)               -- validate payload only
-- T.jwt_claims(claims_schema, header_schema) -- validate both
function T.jwt_claims(claims_schema, header_schema)
  local claims_validator = T.object(claims_schema)
  local header_validator = header_schema and T.object(header_schema)
  local fn = function(v, path)
    if type(v) ~= "string" then return false, path .. " must be a string" end
    local dot1 = v:find(".", 1, true)
    if not dot1 then return false, path .. ": not a valid JWT" end
    local dot2 = v:find(".", dot1 + 1, true)
    if not dot2 then return false, path .. ": not a valid JWT" end
    if header_validator then
      local header_json = b64url_decode(v:sub(1, dot1 - 1))
      if not header_json then
        return false, path .. ": JWT header is not valid base64url"
      end
      local header, err = cjson.decode(header_json)
      if not header then
        return false, path .. ": JWT header is not valid JSON: " .. tostring(err)
      end
      local ok, herr = header_validator(header, path .. "[header]")
      if not ok then return false, herr end
    end
    local payload_json = b64url_decode(v:sub(dot1 + 1, dot2 - 1))
    if not payload_json then
      return false, path .. ": JWT payload is not valid base64url"
    end
    local claims, err = cjson.decode(payload_json)
    if not claims then
      return false, path .. ": JWT payload is not valid JSON: " .. tostring(err)
    end
    return claims_validator(claims, path .. "[claims]")
  end
  T._registry[fn] = { type = "jwt_claims", claims_validator = claims_validator, header_validator = header_validator }
  return fn
end

-- BCP 47 language tag: e.g. "en", "en-US", "zh-Hant", "sr-Latn-CS"
function T.lang_tag()
  local fn = T.string({
    max   = 35,
    match = [[^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$]],
  })
  T._registry[fn] = { type = "lang_tag" }
  return fn
end

-- Standard base64-encoded data (RFC 4648). Pass opts.max to cap length.
function T.base64(opts)
  opts = opts or {}
  local fn = T.string({
    max   = opts.max or 65536,
    match = [[^[A-Za-z0-9+/]*={0,2}$]],
  })
  T._registry[fn] = { type = "base64", opts = opts }
  return fn
end

-- ---------------------------------------------------------------------------
-- HTTP header helpers
-- ---------------------------------------------------------------------------

-- Headers that browsers and HTTP clients send on every request.
-- Use as defaults.allowed_headers in an app policy to enforce a name whitelist.
local _common_request_headers = {
  "accept",
  "accept-encoding",
  "accept-language",
  "authorization",
  "cache-control",
  "connection",
  "cookie",
  "dnt",
  "priority",
  "sec-gpc",
  "if-match",
  "if-modified-since",
  "if-none-match",
  "if-range",
  "if-unmodified-since",
  "origin",
  "pragma",
  "range",
  "referer",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-full-version-list",
  "sec-ch-ua-arch",
  "sec-ch-ua-bitness",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "te",
  "upgrade",
  "upgrade-insecure-requests",
  "user-agent",
  -- WebSocket upgrade headers
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-extensions",
  "sec-websocket-protocol",
}

function T.common_request_headers()
  return _common_request_headers
end

-- Headers added by reverse proxies (nginx, HAProxy, load balancers, CDNs).
-- Include alongside common_request_headers() when OpenResty sits behind
-- another proxy: T.merge_headers(T.common_request_headers(), T.common_proxy_headers())
local _common_proxy_headers = {
  "forwarded",              -- RFC 7239 structured forwarding
  "via",                    -- HTTP intermediary chain
  "x-forwarded-for",        -- client IP chain (de-facto standard)
  "x-forwarded-host",       -- original Host header
  "x-forwarded-port",       -- original port
  "x-forwarded-proto",      -- original scheme (http/https)
  "x-real-ip",              -- single client IP (nginx convention)
  "x-request-id",           -- request tracing
  "x-correlation-id",       -- distributed tracing
  "x-amzn-trace-id",        -- AWS ALB / X-Ray
  "x-cloud-trace-context",  -- GCP Cloud Trace
  "x-b3-traceid",           -- Zipkin/Jaeger B3 tracing
  "x-b3-spanid",
  "x-b3-parentspanid",
  "x-b3-sampled",
}

function T.common_proxy_headers()
  return _common_proxy_headers
end

-- Flatten one or more header name lists into a single array.
-- Usage: T.merge_headers(T.common_request_headers(), T.common_proxy_headers())
function T.merge_headers(...)
  local result = {}
  for i = 1, select("#", ...) do
    for _, name in ipairs(select(i, ...)) do
      result[#result + 1] = name
    end
  end
  return result
end

-- ---------------------------------------------------------------------------
-- Content-Type validators
-- Ordinary string validators; use them in headers = { ["Content-Type"] = ... }
-- or rely on the route-level content_type / content_types shorthand which
-- generates the same check internally.
-- ---------------------------------------------------------------------------

function T.content_type_json()
  return T.string({ max = 256, match = [[^application/json]] })
end

function T.content_type_form()
  return T.string({ max = 256, match = [[^application/x-www-form-urlencoded]] })
end

function T.content_type_multipart()
  return T.string({ max = 512, match = [[^multipart/form-data]] })
end

function T.content_type_octet_stream()
  return T.string({ max = 256, match = [[^application/octet-stream]] })
end

-- ---------------------------------------------------------------------------
-- Authorization header helpers
-- ---------------------------------------------------------------------------

-- ISO 8601 UTC datetime: YYYY-MM-DDTHH:MM:SS[.fractional]Z
function T.iso8601()
  local fn = T.string({ max=32, match=[[^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$]] })
  T._registry[fn] = { type = "iso8601" }
  return fn
end

function T.bearer_token()
  local fn = T.string({ max = 2048, match = [[^Bearer [A-Za-z0-9\-._~+/]+=*$]] })
  T._registry[fn] = { type = "bearer_token" }
  return fn
end

-- ---------------------------------------------------------------------------
-- Sec-GPC header (Global Privacy Control — https://privacycg.github.io/gpc-spec/)
-- Browsers send this only when the user has opted in; the spec mandates value "1".
-- ---------------------------------------------------------------------------
function T.sec_gpc()
  local fn = T.string({ max=1, enum={ ["1"]=true } })
  T._registry[fn] = { type = "sec_gpc" }
  return fn
end

-- ---------------------------------------------------------------------------
-- HTTP Priority header (RFC 9218 Extensible Prioritization Scheme)
-- Structured Field Dictionary with two known members:
--   u=<0-7>  urgency (integer)
--   i        incremental flag; bare "i" means true, "i=?1"/"i=?0" explicit
-- Either member is optional; both orders are permitted.
-- Examples: "u=3"  "u=5, i"  "u=0, i=?1"  "i"  "i=?0, u=7"
-- ---------------------------------------------------------------------------
function T.http_priority()
  local fn = T.string({
    max   = 32,
    match = [[^(?:u=[0-7](?:,\s*i(?:=\?[01])?)?|i(?:=\?[01])?(?:,\s*u=[0-7])?)$]],
  })
  T._registry[fn] = { type = "http_priority" }
  return fn
end

-- ---------------------------------------------------------------------------
-- Query-parameter helpers
-- ---------------------------------------------------------------------------

-- Boolean query param: browsers send the strings "true" or "false"; a bare
-- ?param with no value arrives as an empty string. Wraps T.nullable because
-- an absent optional param arrives as nil from ngx.req.get_uri_args().
function T.bool_query()
  local fn = T.nullable(T.string({ max=5, match=[[^(?:true|false)?$]] }))
  T._registry[fn] = { type = "bool_query" }
  return fn
end

-- Accepts any value; use T.nullable(T.any()) to also accept null.
function T.any()
  local fn = function(v, path) return true end
  T._registry[fn] = { type = "any" }
  return fn
end

-- ---------------------------------------------------------------------------
-- Path-pattern regex fragments
-- These are plain strings, not validator functions.  Concatenate them into
-- route path patterns:  "^/api/ciphers/" .. T.uuid_re .. "$"
-- ---------------------------------------------------------------------------

-- Standard UUID (8-4-4-4-12 hex, any variant/version)
T.uuid_re = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

-- Base64url file ID up to 64 characters (used for attachment and Send file IDs)
T.fileid_re = "[a-zA-Z0-9_-]{1,64}"

return T

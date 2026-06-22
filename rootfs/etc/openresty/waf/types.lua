local ngx = ngx
local T = {}

local function fail(msg)
  return false, msg
end

function T.string(opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "string" then return fail(path .. " must be a string") end
    if opts.min and #v < opts.min then
      return fail(path .. " too short (min " .. opts.min .. ")")
    end
    if opts.max and #v > opts.max then
      return fail(path .. " too long (max " .. opts.max .. ")")
    end
    if opts.match and not ngx.re.find(v, opts.match, "jo") then
      return fail(path .. " invalid format")
    end
    if opts.not_match and ngx.re.find(v, opts.not_match, "jo") then
      return fail(path .. " contains forbidden characters")
    end
    if opts.enum and not opts.enum[v] then
      return fail(path .. " invalid value")
    end
    return true
  end
end

function T.number(opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "number" then return fail(path .. " must be a number") end
    if opts.integer and v % 1 ~= 0 then
      return fail(path .. " must be an integer")
    end
    if opts.min and v < opts.min then
      return fail(path .. " too small (min " .. opts.min .. ")")
    end
    if opts.max and v > opts.max then
      return fail(path .. " too large (max " .. opts.max .. ")")
    end
    return true
  end
end

function T.boolean()
  return function(v, path)
    if type(v) ~= "boolean" then return fail(path .. " must be a boolean") end
    return true
  end
end

function T.uuid()
  return T.string({
    match = [[^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$]]
  })
end

function T.email()
  return T.string({
    min       = 3,
    max       = 320,
    match     = [[^[^@\s]+@[^@\s]+\.[^@\s]+$]],
    not_match = "[\\x00-\\x1f\\x7f<>\"]",
  })
end

-- passes if value is JSON null or Lua nil, otherwise delegates to inner
function T.nullable(inner)
  return function(v, path)
    if v == ngx.null or v == nil then return true end
    return inner(v, path)
  end
end

function T.array(inner, opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "table" then return fail(path .. " must be an array") end
    local n = #v
    if opts.min and n < opts.min then
      return fail(path .. " array too short (min " .. opts.min .. ")")
    end
    if opts.max and n > opts.max then
      return fail(path .. " array too long (max " .. opts.max .. ")")
    end
    for i = 1, n do
      local ok, err = inner(v[i], path .. "[" .. i .. "]")
      if not ok then return false, err end
    end
    return true
  end
end

-- schema: { key = validator, ... }
-- opts.required: { key = true, ... } for mandatory keys
-- unknown keys are always rejected
function T.object(schema, opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "table" then return fail(path .. " must be an object") end
    for key, _ in pairs(v) do
      if not schema[key] then
        return fail(path .. "." .. tostring(key) .. " is not an allowed key")
      end
    end
    for key, validator in pairs(schema) do
      local value = v[key]
      if value ~= nil then
        local ok, err = validator(value, path .. "." .. key)
        if not ok then return false, err end
      elseif opts.required and opts.required[key] then
        return fail(path .. "." .. key .. " is required")
      end
    end
    return true
  end
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

function T.bearer_token()
  return T.string({ max = 2048, match = [[^Bearer [A-Za-z0-9\-._~+/]+=*$]] })
end

return T

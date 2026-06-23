-- --------------------------------------------------------------------------------------
-- 
-- Lua OpenResty Web Application and API Firewall (LOWAAF)
--
-- Concept, Framework and Application Firewall Implementation By:
-- Jeremy Bryan Smith <helamonster@gmail.com>
-- <https://jeremybryansmith.com>
--
-- With assistance from: Claude Sonnet 4.6 <noreply@anthropic.com> 
--
-- --------------------------------------------------------------------------------------
--
-- core.lua : Core Framework Engine : Core engine of request validation
--
-- --------------------------------------------------------------------------------------


local cjson = require "cjson.safe"
local bit   = require "bit"

local core = {}

-- normalize a single value or a table into a list, for fields that accept
-- either the singular form (method = "GET") or plural (methods = {"GET","POST"})
local function list(v)
  if v == nil then return {} end
  if type(v) == "table" then return v end
  return { v }
end

local function any_eq(value, allowed)
  for _, x in ipairs(list(allowed)) do
    if value == x then return true end
  end
  return false
end

local function any_re(value, patterns)
  for _, pat in ipairs(list(patterns)) do
    if ngx.re.find(value, pat, "jo") then return true end
  end
  return false
end

-- try each schema in turn; pass if any matches
local function validate_any_schema(schemas, obj, path)
  local last_err = "no schema matched"
  for _, schema in ipairs(list(schemas)) do
    local ok, err = schema(obj, path)
    if ok then return true end
    last_err = err
  end
  return false, last_err
end

-- IPv4 only; returns nil for IPv6 or malformed addresses
local function ip_to_num(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  return bit.bor(
    bit.lshift(tonumber(a), 24),
    bit.lshift(tonumber(b), 16),
    bit.lshift(tonumber(c),  8),
    tonumber(d)
  )
end

local function cidr_match(ip, cidr)
  local net, prefix = cidr:match("^(.+)/(%d+)$")
  if not net then return ip == cidr end          -- bare IP: exact match
  local ip_num  = ip_to_num(ip)
  local net_num = ip_to_num(net)
  if not ip_num or not net_num then return false end
  local bits = tonumber(prefix)
  if bits == 0 then return true end              -- /0 matches everything
  local mask = bit.bnot(bit.lshift(1, 32 - bits) - 1)
  return bit.band(ip_num, mask) == bit.band(net_num, mask)
end

local function ip_in_list(allow_ips)
  local client_ip = ngx.var.remote_addr
  for _, cidr in ipairs(list(allow_ips)) do
    if cidr_match(client_ip, cidr) then return true end
  end
  return false
end

-- In "block" mode: log, call optional on_deny hook, then send 4xx and exit.
-- In "log" mode (default): log only, return nil so core.run exits cleanly
-- and nginx continues to proxy the request.
local function deny(app, status, reason)
  ngx.log(ngx.WARN, "[waf:", app.name or "?", "] ", reason)
  if (app.mode or "log") == "block" then
    if app.on_deny then pcall(app.on_deny, reason, status) end
    ngx.status = status or 400
    ngx.say("bad request")
    ngx.exit(ngx.status)
    -- ngx.exit() raises internally; code below is unreachable
  end
  -- log mode: fall through, request is allowed
end

local function find_route(app)
  local uri    = ngx.var.uri
  local method = ngx.req.get_method()
  for _, route in ipairs(app.routes) do
    if any_eq(method,  route.methods or route.method) and
       any_re(uri,     route.paths   or route.path)
    then
      return route
    end
  end
  return nil
end

-- Each check_* function calls deny() directly for every violation it finds,
-- then returns false if any violation occurred (true otherwise).
-- In block mode, deny() calls ngx.exit() so only the first violation matters.
-- In log mode, deny() just logs and returns, so the loop continues and every
-- violation in the request is logged before nginx proxies it through.

local function check_ip(app, route)
  local allow_ips = route.allow_ips
  if not allow_ips then return true end
  if ip_in_list(allow_ips) then return true end
  deny(app, 403, "IP " .. (ngx.var.remote_addr or "?") ..
                 " not in allowlist for route '" .. (route.name or "?") .. "'")
  return false
end

-- Validate URI query parameters.
-- route.no_query = true  → deny any query parameters
-- route.query / route.query_schemas → validate args against T.object() schema(s)
-- Repeated params (e.g. ?a=1&a=2) are flattened to the first value.
-- Bare flags (e.g. ?foo) are normalized to "".
local function check_query(app, route)
  local query_schemas = route.query_schemas or route.query
  local no_q          = route.no_query
  local verbose       = app.verbose or 0

  if not no_q and not query_schemas then return true end

  local args = ngx.req.get_uri_args(100)

  if no_q then
    local had_violation = false
    for k, v in pairs(args) do
      local msg = "route '" .. (route.name or "?") .. "' expects no query parameters"
      if verbose >= 1 then
        if type(v) == "table" then v = v[1] end
        msg = msg .. " (got: '" .. tostring(k) .. "=" .. tostring(v) .. "')"
      end
      deny(app, 400, msg)
      had_violation = true
    end
    if had_violation then return false end
    return true
  end

  local flat = {}
  for k, v in pairs(args) do
    if type(v) == "table" then flat[k] = v[1]
    elseif v == true      then flat[k] = ""
    else                       flat[k] = v
    end
  end

  local ok, err = validate_any_schema(query_schemas, flat, "?")
  if not ok then
    local prefix = "route '" .. (route.name or "?") .. "': "
    for line in err:gmatch("[^\n]+") do
      deny(app, 400, prefix .. line)
    end
    return false
  end

  if verbose >= 2 then
    for k, v in pairs(flat) do
      ngx.log(ngx.INFO, "[waf:", (app.name or "?"), "] allowed query '",
              tostring(k), "' = '", tostring(v), "'")
    end
  end

  return true
end

-- These headers are always permitted regardless of the allowed_headers list.
-- content-type and content-length are validated separately (via check_headers
-- and check_body respectively) and must not be blocked at the name level.
local ALWAYS_ALLOWED = {
  ["host"]           = true,
  ["content-type"]   = true,
  ["content-length"] = true,
}

-- Build a validator function from a content_type / content_types string list.
-- Checks that the Content-Type header value starts with one of the given types.
local function make_ct_validator(allowed_types)
  local types = list(allowed_types)
  return function(v, path)
    if type(v) ~= "string" then return false, path .. " must be a string" end
    for _, expected in ipairs(types) do
      local escaped = ngx.re.gsub(expected, [[([.+\-])]], [[\$1]], "jo")
      if ngx.re.find(v, "^" .. escaped, "jo") then return true end
    end
    return false, path .. ": '" .. v .. "' is not an accepted content-type"
  end
end

-- Validate request header names against the allowlist, and header values
-- against any registered validators.  Also handles the route-level
-- content_type / content_types shorthand by converting it into a Content-Type
-- header validator so the two mechanisms are unified.
--
-- Name allowlist is only enforced when defaults.allowed_headers is set.
-- Value validators (defaults.headers, route.headers) always run when present.
local function check_headers(app, route)
  local defaults  = app.defaults or {}
  local ct_types  = route.content_types or route.content_type
  local verbose   = app.verbose or 0

  local has_policy = defaults.allowed_headers or defaults.headers
                     or route.headers or route.extra_headers or ct_types
  if not has_policy then return true end

  local req_headers = ngx.req.get_headers(100)

  -- name allowlist: only enforced when the app declares defaults.allowed_headers
  if defaults.allowed_headers then
    local allowed = {}
    for _, name in ipairs(list(defaults.allowed_headers)) do
      allowed[name:lower()] = true
    end
    -- headers with registered validators are implicitly allowed by name
    for name, _ in pairs(defaults.headers  or {}) do allowed[name:lower()] = true end
    for name, _ in pairs(route.headers     or {}) do allowed[name:lower()] = true end
    for _, name  in ipairs(list(route.extra_headers or {})) do allowed[name:lower()] = true end
    if ct_types then allowed["content-type"] = true end

    local had_violation = false
    for name, _ in pairs(req_headers) do
      local lower = name:lower()
      if not ALWAYS_ALLOWED[lower] and not allowed[lower] then
        local msg = "header '" .. name .. "' is not allowed"
        if verbose >= 1 then
          local v = req_headers[name]
          if type(v) == "table" then v = v[1] end
          msg = msg .. " (value: '" .. tostring(v or "") .. "')"
        end
        deny(app, 400, msg)
        had_violation = true
      end
    end
    if had_violation and not ngx.ctx.waf_log_mode then return false end
  end

  -- value validators: defaults.headers provides the base, route.headers overrides
  local validators = {}
  for name, v in pairs(defaults.headers or {}) do
    validators[name:lower()] = v
  end
  for name, v in pairs(route.headers or {}) do
    validators[name:lower()] = v
  end
  -- content_type / content_types shorthand: auto-generate a validator unless
  -- the app already registered one via headers = { ["Content-Type"] = ... }
  if ct_types and not validators["content-type"] then
    validators["content-type"] = make_ct_validator(ct_types)
  end

  local had_violation = false
  for name_lower, validator in pairs(validators) do
    local value = req_headers[name_lower]
    if value ~= nil then
      -- ngx.req.get_headers() returns a table when a header appears multiple times
      if type(value) == "table" then value = value[1] end
      local ok, err = validator(tostring(value), "header[" .. name_lower .. "]")
      if not ok then
        if verbose >= 1 then
          err = err .. " (value: '" .. tostring(value) .. "')"
        end
        deny(app, 400, err)
        had_violation = true
      end
    end
  end
  if had_violation then return false end

  -- verbose level 2: log every header that was explicitly allowed
  if verbose >= 2 then
    for name, value in pairs(req_headers) do
      if type(value) == "table" then value = value[1] end
      ngx.log(ngx.INFO, "[waf:", (app.name or "?"), "] allowed header '",
              name, "' = '", tostring(value or ""), "'")
    end
  end

  return true
end

local function check_body(app, route)
  local max_body     = route.max_body or (app.defaults and app.defaults.max_body)
  local json_schemas = route.json_schemas or route.json
  local form_schemas = route.form_schemas or route.form

  if route.no_body then
    local len = tonumber(ngx.var.http_content_length or "0") or 0
    if len > 0 then
      deny(app, 400, "route '" .. (route.name or "?") .. "' expects no body")
      return false
    end
    return true
  end

  -- enforce max_body unconditionally, even when no schema is declared
  if max_body then
    local len = tonumber(ngx.var.http_content_length or "0") or 0
    if len > max_body then
      deny(app, 400, "route '" .. (route.name or "?") .. "': body too large")
      return false
    end
  end

  if json_schemas then
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    local obj, err = cjson.decode(body)
    if not obj then
      deny(app, 400, "route '" .. (route.name or "?") ..
                     "': invalid JSON: " .. tostring(err))
      return false
    end
    local ok, verr = validate_any_schema(json_schemas, obj, "$")
    if not ok then
      local prefix = "route '" .. (route.name or "?") .. "': "
      for line in verr:gmatch("[^\n]+") do
        deny(app, 400, prefix .. line)
      end
      return false
    end
    return true
  end

  if form_schemas then
    ngx.req.read_body()
    local args = ngx.req.get_post_args(200)
    local ok, verr = validate_any_schema(form_schemas, args, "$")
    if not ok then
      local prefix = "route '" .. (route.name or "?") .. "': "
      for line in verr:gmatch("[^\n]+") do
        deny(app, 400, prefix .. line)
      end
      return false
    end
    return true
  end

  return true
end

function core.run(app)
  ngx.ctx.waf_verbose  = app.verbose or 0
  ngx.ctx.waf_log_mode = (app.mode or "log") == "log"

  local method = ngx.req.get_method()

  -- 1. global method check — always stop: no meaningful further checks without a valid method
  if app.defaults and app.defaults.allowed_methods then
    if not app.defaults.allowed_methods[method] then
      deny(app, 405, "method not globally allowed: " .. method)
      return
    end
  end

  -- 2. route match — always stop: subsequent checks require a matched route
  local route = find_route(app)
  if not route then
    deny(app, 404, "no route matched: " .. method .. " " .. ngx.var.uri)
    return
  end

  -- 3–6. Each check calls deny() for every violation it finds.
  -- In block mode, deny() calls ngx.exit() so the request stops at the first violation.
  -- In log mode, deny() only logs, so all checks run and every violation is logged.
  check_ip(app, route)
  check_query(app, route)
  check_headers(app, route)
  check_body(app, route)
end

return core

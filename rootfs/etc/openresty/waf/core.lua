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

local function check_ip(route)
  local allow_ips = route.allow_ips
  if not allow_ips then return true end
  if ip_in_list(allow_ips) then return true end
  return false, "IP " .. (ngx.var.remote_addr or "?") ..
                " not in allowlist for route '" .. (route.name or "?") .. "'"
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

    for name, _ in pairs(req_headers) do
      local lower = name:lower()
      if not ALWAYS_ALLOWED[lower] and not allowed[lower] then
        return false, "header '" .. name .. "' is not allowed"
      end
    end
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

  for name_lower, validator in pairs(validators) do
    local value = req_headers[name_lower]
    if value ~= nil then
      -- ngx.req.get_headers() returns a table when a header appears multiple times
      if type(value) == "table" then value = value[1] end
      local ok, err = validator(tostring(value), "header[" .. name_lower .. "]")
      if not ok then return false, err end
    end
  end

  return true
end

local function check_body(app, route)
  local max_body = route.max_body or (app.defaults and app.defaults.max_body)

  if route.no_body then
    local len = tonumber(ngx.var.http_content_length or "0") or 0
    if len > 0 then
      return false, "route '" .. (route.name or "?") .. "' expects no body"
    end
    return true
  end

  local json_schemas = route.json_schemas or route.json
  local form_schemas = route.form_schemas or route.form

  if json_schemas then
    local len = tonumber(ngx.var.http_content_length or "0") or 0
    if max_body and len > max_body then
      return false, "route '" .. (route.name or "?") .. "': body too large"
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    local obj, err = cjson.decode(body)
    if not obj then
      return false, "route '" .. (route.name or "?") ..
                    "': invalid JSON: " .. tostring(err)
    end
    local ok, verr = validate_any_schema(json_schemas, obj, "$")
    if not ok then
      return false, "route '" .. (route.name or "?") .. "': " .. verr
    end
    return true
  end

  if form_schemas then
    local len = tonumber(ngx.var.http_content_length or "0") or 0
    if max_body and len > max_body then
      return false, "route '" .. (route.name or "?") .. "': body too large"
    end
    ngx.req.read_body()
    local args = ngx.req.get_post_args(200)
    local ok, verr = validate_any_schema(form_schemas, args, "$")
    if not ok then
      return false, "route '" .. (route.name or "?") .. "': " .. verr
    end
    return true
  end

  return true
end

function core.run(app)
  local method = ngx.req.get_method()

  -- 1. global method check
  if app.defaults and app.defaults.allowed_methods then
    if not app.defaults.allowed_methods[method] then
      return deny(app, 405, "method not globally allowed: " .. method)
    end
  end

  -- 2. route match
  local route = find_route(app)
  if not route then
    return deny(app, 404, "no route matched: " .. method .. " " .. ngx.var.uri)
  end

  -- 3. IP allowlist
  local ok, err = check_ip(route)
  if not ok then return deny(app, 403, err) end

  -- 4. headers (name allowlist + value validation, includes content-type)
  ok, err = check_headers(app, route)
  if not ok then return deny(app, 400, err) end

  -- 5. body size, no-body, JSON schema, form schema
  ok, err = check_body(app, route)
  if not ok then return deny(app, 400, err) end
end

return core

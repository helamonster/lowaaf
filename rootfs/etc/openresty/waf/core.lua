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

local function check_content_type(route)
  local allowed = route.content_types or route.content_type
  if not allowed then return true end
  local ct = ngx.var.http_content_type or ""
  for _, expected in ipairs(list(allowed)) do
    -- escape regex metacharacters that appear in media-type strings
    local escaped = ngx.re.gsub(expected, [[([.+\-])]], [[\$1]], "jo")
    if ngx.re.find(ct, "^" .. escaped, "jo") then return true end
  end
  return false, "content-type '" .. ct ..
                "' not accepted for route '" .. (route.name or "?") .. "'"
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

  -- 4. content-type
  ok, err = check_content_type(route)
  if not ok then return deny(app, 415, err) end

  -- 5–8. body size, no-body, JSON schema, form schema
  ok, err = check_body(app, route)
  if not ok then return deny(app, 400, err) end
end

return core

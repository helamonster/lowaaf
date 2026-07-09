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

-- Returns nil for IPv6 or malformed addresses.
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

-- Parses a colon-separated IPv6 group string into an array of 16-bit integers.
-- Returns an empty table for "" (the part absorbed by "::").
-- Returns nil on any parse error (empty segment from embedded "::", bad hex, group > 4 chars).
local function parse_ipv6_groups(s)
  if s == "" then return {} end
  local groups = {}
  for g in (s .. ":"):gmatch("([^:]*):") do
    if #g == 0 or #g > 4 then return nil end
    local n = tonumber(g, 16)
    if not n then return nil end
    groups[#groups + 1] = n
  end
  return groups
end

-- Expands a compressed or full IPv6 address to 16 bytes, or returns nil on error.
local function ipv6_to_bytes(ip)
  local before_dc, after_dc = ip:match("^(.*)::(.*)$")
  local groups

  if before_dc then
    local lg = parse_ipv6_groups(before_dc)
    local rg = parse_ipv6_groups(after_dc)
    if not lg or not rg then return nil end
    local zeros = 8 - #lg - #rg
    if zeros < 1 then return nil end   -- "::" must replace at least one group
    groups = {}
    for _, v in ipairs(lg)   do groups[#groups + 1] = v end
    for _     = 1, zeros     do groups[#groups + 1] = 0 end
    for _, v in ipairs(rg)   do groups[#groups + 1] = v end
  else
    groups = parse_ipv6_groups(ip)
    if not groups then return nil end
  end

  if #groups ~= 8 then return nil end

  local bytes = {}
  for _, g in ipairs(groups) do
    bytes[#bytes + 1] = math.floor(g / 256)
    bytes[#bytes + 1] = g % 256
  end
  return bytes
end

local function cidr_match(ip, cidr)
  local net, prefix = cidr:match("^(.+)/(%d+)$")

  if ip:find(":", 1, true) then
    -- IPv6
    local ip_bytes  = ipv6_to_bytes(ip)
    local net_bytes = ipv6_to_bytes(net or cidr)
    if not ip_bytes or not net_bytes then return false end
    if not net then
      -- Bare IPv6 address: compare all 16 bytes (handles compressed vs full forms)
      for i = 1, 16 do
        if ip_bytes[i] ~= net_bytes[i] then return false end
      end
      return true
    end
    local bits = tonumber(prefix)
    if not bits or bits < 0 or bits > 128 then return false end
    if bits == 0 then return true end
    local full = math.floor(bits / 8)
    local rem  = bits % 8
    for i = 1, full do
      if ip_bytes[i] ~= net_bytes[i] then return false end
    end
    if rem > 0 then
      local mask = bit.band(bit.bnot(bit.lshift(1, 8 - rem) - 1), 0xff)
      if bit.band(ip_bytes[full + 1], mask) ~=
         bit.band(net_bytes[full + 1], mask) then
        return false
      end
    end
    return true
  end

  -- IPv4
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
  if not ngx.ctx.waf_log_mode then
    if app.on_deny then pcall(app.on_deny, reason, status) end
    ngx.header["X-WAF"] = "block"
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

-- These headers are always permitted regardless of the allowed_headers list.
-- content-type and content-length are validated separately (via check_headers
-- and check_body respectively) and must not be blocked at the name level.
local ALWAYS_ALLOWED = {
  ["host"]           = true,
  ["content-type"]   = true,
  ["content-length"] = true,
}

-- Builds a content-type validator from a string or list of accepted types.
-- Content-type patterns are pre-escaped at call time; the returned closure
-- only runs ngx.re.find on each request.
local function make_ct_validator(allowed_types)
  local types = list(allowed_types)
  local patterns = {}
  for i, expected in ipairs(types) do
    patterns[i] = "^" .. ngx.re.gsub(expected, [[([.+\-])]], [[\$1]], "jo")
  end
  return function(v, path)
    if type(v) ~= "string" then return false, path .. " must be a string" end
    for _, pat in ipairs(patterns) do
      if ngx.re.find(v, pat, "jo") then return true end
    end
    return false, path .. ": '" .. v .. "' is not an accepted content-type"
  end
end

-- Precomputes per-route header policy caches so check_headers avoids
-- rebuilding them on every request.  Called once per app table, lazily on
-- the first core.run() call (access phase, so ngx.re is fully available).
local function prepare(app)
  if app._prepared then return end

  local defaults = app.defaults or {}

  -- Base allowed-name set and base validators come from app.defaults.
  -- These are shared across all routes; per-route fields are merged below.
  local base_allowed
  local base_validators = {}

  if defaults.allowed_headers then
    base_allowed = {}
    for _, name in ipairs(list(defaults.allowed_headers)) do
      base_allowed[name:lower()] = true
    end
  end

  for name, v in pairs(defaults.headers or {}) do
    local lower = name:lower()
    base_validators[lower] = v
    if base_allowed then base_allowed[lower] = true end  -- implicitly allowed
  end

  for _, route in ipairs(app.routes or {}) do
    local ct_types   = route.content_types or route.content_type
    local has_policy = defaults.allowed_headers or defaults.headers
                       or route.headers or route.extra_headers or ct_types

    if not has_policy then
      route._cache = false  -- sentinel: skip all header checks for this route
    else
      local c = {}

      -- Merge allowed-name set: defaults + route-specific additions
      if base_allowed then
        c.allowed = {}
        for k, val in pairs(base_allowed) do c.allowed[k] = val end
        for name, _ in pairs(route.headers or {}) do c.allowed[name:lower()] = true end
        for _, name in ipairs(list(route.extra_headers or {})) do
          c.allowed[name:lower()] = true
        end
        if ct_types then c.allowed["content-type"] = true end
      end

      -- Merge value validators: defaults, then route overrides
      c.validators = {}
      for k, v in pairs(base_validators) do c.validators[k] = v end
      for name, v in pairs(route.headers or {}) do c.validators[name:lower()] = v end

      -- Content-type shorthand: build validator unless app already registered one
      if ct_types and not c.validators["content-type"] then
        c.validators["content-type"] = make_ct_validator(ct_types)
      end

      route._cache = c
    end
  end

  app._prepared = true
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

-- Validates request header names against the allowlist, and header values
-- against any registered validators.  Reads from the per-route cache built
-- by prepare() — no set/map construction happens at request time.
--
-- Name allowlist is only enforced when defaults.allowed_headers is set.
-- Value validators (defaults.headers, route.headers) always run when present.
local function check_headers(app, route)
  local c = route._cache
  if c == false then return true end  -- no header policy for this route

  local verbose     = app.verbose or 0
  local req_headers = ngx.req.get_headers(100)

  -- Name allowlist: only enforced when the app declares defaults.allowed_headers
  if c.allowed then
    local had_violation = false
    for name, _ in pairs(req_headers) do
      local lower = name:lower()
      if not ALWAYS_ALLOWED[lower] and not c.allowed[lower] then
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

  -- Value validators: defaults.headers provides the base, route.headers overrides
  local had_violation = false
  for name_lower, validator in pairs(c.validators) do
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

-- Reads the full request body, whether it landed in memory or spilled to a
-- temp file (exceeded client_body_buffer_size).  Assumes ngx.req.read_body()
-- has already been called.
local function read_full_body()
  local body = ngx.req.get_body_data()
  if not body then
    local fname = ngx.req.get_body_file()
    if fname then
      local f = io.open(fname, "r")
      if f then body = f:read("*all"); f:close() end
    end
  end
  return body or ""
end

-- Buffered multipart/form-data parser.  MediaWiki-style edit forms (and most
-- app forms in general) are small enough to fit comfortably under max_body,
-- so unlike a streaming upload handler this simply parses the whole body at
-- once — consistent with how the JSON branch already buffers full bodies.
-- File parts (a "filename" attribute on Content-Disposition) are recorded as
-- their filename string rather than their raw bytes; validating uploaded
-- file *content* is out of scope for this parser.
local function parse_multipart(body, boundary)
  local fields = {}
  if body == "" or not boundary or boundary == "" then return fields end

  local delim = "--" .. boundary
  local pos = 1
  while true do
    local s = body:find(delim, pos, true)
    if not s then break end
    local part_start = s + #delim
    if body:sub(part_start, part_start + 1) == "--" then break end  -- final boundary

    local next_at = body:find(delim, part_start, true)
    local part_end = next_at or (#body + 1)
    local part = body:sub(part_start, part_end - 1)

    local head, content = part:match("^\r?\n(.-)\r?\n\r?\n(.*)$")
    if head then
      content = content:gsub("\r?\n$", "")
      local name = head:match('name="([^"]*)"')
      -- A part with a filename= attribute is a real file upload - its
      -- "content" is the raw file body, which can be many MB and was never
      -- meant to be schema-validated as a normal string field (see the
      -- module comment above). Record just the filename instead, matching
      -- what the rest of this file already assumes file fields look like.
      local filename = head:match('filename="([^"]*)"')
      if filename then content = filename end
      if name then
        if fields[name] ~= nil then
          if type(fields[name]) ~= "table" then fields[name] = { fields[name] } end
          fields[name][#fields[name] + 1] = content
        else
          fields[name] = content
        end
      end
    end

    pos = part_end
  end

  return fields
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
    local obj, err = cjson.decode(read_full_body())
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
    local content_type = ngx.req.get_headers()["content-type"] or ""
    local args
    if content_type:find("multipart/form-data", 1, true) then
      local boundary = content_type:match('boundary="?([^";]+)"?')
      args = parse_multipart(read_full_body(), boundary)
    else
      -- ngx.req.get_post_args() only works when the body stayed in nginx's
      -- in-memory buffer; a body larger than client_body_buffer_size (an
      -- 8-16K default, easily exceeded by a real wikitext edit) gets spilled
      -- to a temp file instead, and get_post_args() then fails outright
      -- rather than falling back to it - silently turning every such
      -- request into a deny. Parsing the raw body text ourselves sidesteps
      -- that entirely: read_full_body() already has the temp-file fallback.
      args = ngx.decode_args(read_full_body(), 200)
    end
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
  prepare(app)

  ngx.ctx.waf_verbose  = app.verbose or 0
  -- /tmp/waf-block-mode can be created inside the container (via docker exec)
  -- to force block mode without reloading nginx.  Checked per-request so it
  -- takes effect immediately; used by online-test-full.
  local _bmf = io.open("/tmp/waf-block-mode", "r")
  local _mode = _bmf and (_bmf:close() or "block") or (app.mode or "log")
  ngx.ctx.waf_log_mode = _mode == "log"

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

-- Returns an on_deny callback that bans the client IP in an ipset.
-- Runs via a zero-delay timer so the response is never delayed.
-- The ipset must already exist before OpenResty starts:
--   ipset create waf-blocklist hash:ip timeout 3600
-- Wire it up with nftables or iptables, then add to the app policy:
--   local core = require "waf.core"
--   on_deny = core.ipset_deny_hook("waf-blocklist")
--
-- opts.timeout      seconds until ban auto-expires (default 3600)
-- opts.skip_private skip RFC 1918 / loopback IPs (default true)
function core.ipset_deny_hook(set_name, opts)
  opts = opts or {}
  local ban_timeout = opts.timeout or 3600
  local skip_priv   = opts.skip_private ~= false
  local private_re  = [[^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fd[\da-f]{2}:)]]

  return function(reason, status)
    local ip = ngx.var and ngx.var.remote_addr
    if not ip then return end
    if skip_priv and ngx.re.find(ip, private_re, "joi") then return end
    local cmd = "ipset add " .. set_name .. " " .. ip
                .. " timeout " .. tostring(ban_timeout) .. " 2>/dev/null"
    ngx.timer.at(0, function() os.execute(cmd) end)
  end
end

return core

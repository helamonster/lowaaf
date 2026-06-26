-- test/runner.lua
-- Run as:  resty -I /etc/openresty test/runner.lua [app-name]
--
-- Enumerates every route in the app and runs:
--   1. Valid request  → expect WAF to allow
--   2. Wrong method   → expect WAF to deny
--   3. Body-schema invalids (per-field boundary tests) → expect WAF to deny
--   4. Form-schema invalids → expect WAF to deny
--   5. Query-schema invalids → expect WAF to deny
--
-- A route is skipped (not failed) when no valid body can be auto-generated
-- (e.g. jwt_claims in query params).

-- package.path is provided by:  resty -I rootfs/etc/openresty test/runner.lua

local cjson = require "cjson.safe"
local mock  = require "test.mock_ngx"
local gen   = require "test.gen"
local core  = require "waf.core"

-- ── Load app ──────────────────────────────────────────────────────────────────

local app_name = arg and arg[1] or "vaultwarden"
local ok, app = pcall(require, "waf.apps." .. app_name)
if not ok then
  io.stderr:write("Cannot load waf.apps." .. app_name .. ": " .. tostring(app) .. "\n")
  os.exit(1)
end

-- Force block mode so denied requests exit early (cleaner detection).
-- We save and restore around each test.
local saved_mode = app.mode
app.mode = "block"

-- ── Test infrastructure ───────────────────────────────────────────────────────

local pass_count = 0
local fail_count = 0
local skip_count = 0
local results    = {}  -- { route_name, label, outcome, detail }

local function record(route_name, label, outcome, detail)
  results[#results+1] = { route=route_name, label=label, outcome=outcome, detail=detail or "" }
  if outcome == "PASS" then pass_count = pass_count + 1
  elseif outcome == "FAIL" then fail_count = fail_count + 1
  else skip_count = skip_count + 1
  end
end

-- Run core.run(app) with the given request; return true if WAF allowed it.
local function run_request(req)
  mock.set_request(req)
  local ok, err = pcall(core.run, app)
  if not ok and err ~= mock._EXIT then
    -- Unexpected Lua error (not a WAF exit sentinel)
    error(err)
  end
  return not mock.was_denied()
end

-- ── Route list helper ─────────────────────────────────────────────────────────

local function route_methods(route)
  local m = route.methods or route.method
  if type(m) == "string" then return { m }
  elseif type(m) == "table" then return m
  end
  return {}
end

local function route_paths(route)
  local p = route.paths or route.path
  if type(p) == "string" then return { p }
  elseif type(p) == "table" then return p
  end
  return {}
end

-- Pick a method NOT in the route's allowed list (for negative method test).
-- Prefer a method that is also NOT in app.defaults.allowed_methods — that way
-- the deny fires at the global method check regardless of which other routes
-- share the same URI, avoiding false failures on sibling routes.
local ALL_METHODS = { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" }
local function wrong_method(route)
  local allowed = {}
  for _, m in ipairs(route_methods(route)) do allowed[m] = true end
  local global_ok = app.defaults.allowed_methods or {}
  -- 1. Try PATCH / HEAD / TRACE — blocked globally, no shared-URI ambiguity.
  for _, m in ipairs({ "PATCH", "HEAD", "TRACE" }) do
    if not allowed[m] and not global_ok[m] then return m end
  end
  -- 2. Fall back to a globally-allowed method not used by this route.
  --    May produce a false "allow" if another route shares the URI — acceptable.
  for _, m in ipairs(ALL_METHODS) do
    if not allowed[m] and global_ok[m] then return m end
  end
  return nil
end

-- ── JSON body serialization ───────────────────────────────────────────────────

-- cjson refuses to encode nil at the top level and tables with nil values work
-- by omission, which is what we want. Guard against un-encodable values.
local function encode_body(v)
  if v == nil then return nil end
  local s, err = cjson.encode(v)
  return s  -- nil on error → caller treats as unencodable
end

-- ── Per-route test runner ─────────────────────────────────────────────────────

local function test_route(route)
  local name    = route.name or "?"
  local uri     = gen.route_uri(route)
  local methods = route_methods(route)
  if #methods == 0 then
    record(name, "no methods defined", "SKIP")
    return
  end
  local method = methods[1]

  -- Determine what headers are needed for this route.
  local base_headers = {
    ["User-Agent"]  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " ..
                      "AppleWebKit/537.36 (KHTML, like Gecko) " ..
                      "Chrome/120.0 Safari/537.36 Bitwarden/2026.5.0",
  }
  local ct = route.content_types or route.content_type
  if ct then
    local first_ct = type(ct) == "table" and ct[1] or ct
    base_headers["Content-Type"] = first_ct
  end

  -- ── 1. Valid request ────────────────────────────────────────────────────────

  -- Build valid body/form/query
  local valid_body, valid_form, valid_query

  local json_schema = route.json_schemas and route.json_schemas[1] or route.json
  local form_schema = route.form_schemas and route.form_schemas[1] or route.form
  local query_schema = route.query_schemas and route.query_schemas[1] or route.query

  if json_schema then
    local v = gen.valid_value(json_schema)
    if v == nil then
      record(name, "valid request", "SKIP", "cannot auto-gen JSON body")
    else
      valid_body = encode_body(v)
      if not valid_body then
        record(name, "valid request", "SKIP", "body not JSON-encodable")
      else
        local allowed = run_request({
          method  = method,
          uri     = uri,
          headers = base_headers,
          body    = valid_body,
        })
        if allowed then
          record(name, "valid " .. method .. " " .. uri, "PASS")
        else
          record(name, "valid " .. method .. " " .. uri, "FAIL",
                 "valid request was denied")
        end
      end
    end
    -- Test every additional schema (json_schemas[2..n] must also be accepted)
    if route.json_schemas then
      for i = 2, #route.json_schemas do
        local alt = route.json_schemas[i]
        local av  = gen.valid_value(alt)
        if av ~= nil then
          local ab = encode_body(av)
          if ab then
            local ok = run_request({ method=method, uri=uri, headers=base_headers, body=ab })
            if ok then
              record(name, "valid body (schema " .. i .. ")", "PASS")
            else
              record(name, "valid body (schema " .. i .. ")", "FAIL",
                     "schema " .. i .. " valid body was denied")
            end
          end
        end
      end
    end
  elseif form_schema then
    local v = gen.valid_value(form_schema)
    if v == nil then
      record(name, "valid request", "SKIP", "cannot auto-gen form body")
    else
      valid_form = v
      local allowed = run_request({
        method  = method,
        uri     = uri,
        headers = base_headers,
        form    = valid_form,
      })
      if allowed then
        record(name, "valid " .. method .. " " .. uri, "PASS")
      else
        record(name, "valid " .. method .. " " .. uri, "FAIL",
               "valid request was denied")
      end
    end
  else
    -- No body schema: valid request has no body; include query params if declared.
    local valid_query_obj
    if query_schema then
      local qv = gen.valid_value(query_schema)
      if qv ~= nil then valid_query_obj = qv end
    end
    local allowed = run_request({
      method  = method,
      uri     = uri,
      headers = base_headers,
      query   = valid_query_obj,
    })
    if allowed then
      record(name, "valid " .. method .. " " .. uri, "PASS")
    else
      record(name, "valid " .. method .. " " .. uri, "FAIL",
             "valid request was denied")
    end
  end

  -- ── 2. Wrong method ─────────────────────────────────────────────────────────

  local bad_method = wrong_method(route)
  if bad_method then
    local denied = not run_request({
      method  = bad_method,
      uri     = uri,
      headers = base_headers,
    })
    if denied then
      record(name, "wrong method " .. bad_method, "PASS")
    else
      record(name, "wrong method " .. bad_method, "FAIL",
             "expected deny, got allow")
    end
  end

  -- ── 3. Unknown header rejected ─────────────────────────────────────────────

  if app.defaults.allowed_headers then
    local bad_headers = {}
    for k, v in pairs(base_headers) do bad_headers[k] = v end
    bad_headers["X-Waf-Test-Unknown"] = "1"
    local denied = not run_request({
      method  = method,
      uri     = uri,
      headers = bad_headers,
    })
    if denied then
      record(name, "unknown header rejected", "PASS")
    else
      record(name, "unknown header rejected", "FAIL",
             "expected deny for unlisted header X-Waf-Test-Unknown")
    end
  end

  -- ── 4. IP allowlist ────────────────────────────────────────────────────────

  if route.allow_ips then
    local denied = not run_request({
      method      = method,
      uri         = uri,
      headers     = base_headers,
      remote_addr = "1.2.3.4",   -- guaranteed not in any real allowlist
    })
    if denied then
      record(name, "blocked IP 1.2.3.4", "PASS")
    else
      record(name, "blocked IP 1.2.3.4", "FAIL", "expected deny for non-allowed IP")
    end
  end

  -- ── 5. Body on no_body route ────────────────────────────────────────────────

  if route.no_body then
    local denied = not run_request({
      method  = method,
      uri     = uri,
      headers = base_headers,
      body    = '{"x":1}',
    })
    if denied then
      record(name, "body on no_body route", "PASS")
    else
      record(name, "body on no_body route", "FAIL",
             "expected deny, got allow")
    end
  end

  -- ── 6. Max body size ───────────────────────────────────────────────────────

  local max_body = route.max_body or (app.defaults and app.defaults.max_body)
  if max_body and not route.no_body then
    local denied = not run_request({
      method         = method,
      uri            = uri,
      headers        = base_headers,
      content_length = max_body + 1,
      body           = "",
    })
    if denied then
      record(name, "body size max_body+1", "PASS")
    else
      record(name, "body size max_body+1", "FAIL", "expected deny for oversized body")
    end
  end

  -- ── 7. Wrong content-type ──────────────────────────────────────────────────

  local ct = route.content_types or route.content_type
  if ct and not route.no_body then
    local wrong_headers = {}
    for k, v in pairs(base_headers) do wrong_headers[k] = v end
    wrong_headers["Content-Type"] = "text/plain"
    local denied = not run_request({
      method  = method,
      uri     = uri,
      headers = wrong_headers,
      body    = '{"x":1}',
    })
    if denied then
      record(name, "wrong content-type text/plain", "PASS")
    else
      record(name, "wrong content-type text/plain", "FAIL",
             "expected deny, got allow")
    end
  end

  -- ── 8. Malformed / wrong-type JSON body ────────────────────────────────────

  if json_schema then
    local bad_bodies = {
      { body = "{bad json}",      label = "syntax error" },
      { body = '"just a string"', label = "JSON string instead of object" },
      { body = "[1,2,3]",         label = "JSON array instead of object" },
      { body = "123",             label = "JSON number instead of object" },
      { body = "true",            label = "JSON boolean instead of object" },
      { body = "null",            label = "JSON null instead of object" },
      { body = "",                label = "empty body" },
    }
    for _, case in ipairs(bad_bodies) do
      local denied = not run_request({
        method  = method,
        uri     = uri,
        headers = base_headers,
        body    = case.body,
      })
      if denied then
        record(name, "malformed json: " .. case.label, "PASS")
      else
        record(name, "malformed json: " .. case.label, "FAIL",
               "expected deny, got allow")
      end
    end
  end

  -- ── 9. JSON body invalids ───────────────────────────────────────────────────
  -- For multi-schema routes: only test values that fail EVERY schema.
  -- A body valid for any one schema is correctly allowed by the WAF.

  if json_schema then
    local all_schemas = route.json_schemas or { json_schema }

    -- Collect candidates from every schema, keep those that fail all of them.
    local seen           = {}
    local cross_invalids = {}
    for _, schema in ipairs(all_schemas) do
      for _, pair in ipairs(gen.invalid_values(schema)) do
        if not seen[pair.label] then
          seen[pair.label] = true
          local fails_all = true
          for _, other in ipairs(all_schemas) do
            ngx.ctx = { waf_verbose = 0, waf_log_mode = false }
            if other(pair.value, "$") then fails_all = false; break end
          end
          if fails_all then cross_invalids[#cross_invalids+1] = pair end
        end
      end
    end

    for _, pair in ipairs(cross_invalids) do
      local body_str = encode_body(pair.value)
      if body_str then
        local denied = not run_request({
          method  = method,
          uri     = uri,
          headers = base_headers,
          body    = body_str,
        })
        if denied then
          record(name, "json invalid: " .. pair.label, "PASS")
        else
          record(name, "json invalid: " .. pair.label, "FAIL",
                 "expected deny, got allow")
        end
      end
    end
  end

  -- ── 10. Form body invalids ──────────────────────────────────────────────────

  if form_schema then
    local invalids = gen.invalid_values(form_schema)
    for _, pair in ipairs(invalids) do
      if type(pair.value) == "table" then
        local denied = not run_request({
          method  = method,
          uri     = uri,
          headers = base_headers,
          form    = pair.value,
        })
        if denied then
          record(name, "form invalid: " .. pair.label, "PASS")
        else
          record(name, "form invalid: " .. pair.label, "FAIL",
                 "expected deny, got allow")
        end
      end
    end
  end

  -- ── 11. Query invalids ──────────────────────────────────────────────────────

  if query_schema then
    local invalids = gen.invalid_values(query_schema)
    for _, pair in ipairs(invalids) do
      if type(pair.value) == "table" then
        local denied = not run_request({
          method  = method,
          uri     = uri,
          headers = base_headers,
          query   = pair.value,
        })
        if denied then
          record(name, "query invalid: " .. pair.label, "PASS")
        else
          record(name, "query invalid: " .. pair.label, "FAIL",
                 "expected deny, got allow")
        end
      end
    end
  end
end

-- ── Run all routes ────────────────────────────────────────────────────────────

io.write(string.format("[%s] Running tests...\n", app_name))

for _, route in ipairs(app.routes) do
  local ok, err = pcall(test_route, route)
  if not ok then
    local name = route.name or "?"
    record(name, "ERROR", "FAIL", tostring(err))
  end
end

app.mode = saved_mode

-- ── Print results ─────────────────────────────────────────────────────────────

local total = pass_count + fail_count + skip_count

-- Print failures first so they're easy to spot
local any_fail = false
for _, r in ipairs(results) do
  if r.outcome == "FAIL" then
    if not any_fail then
      io.write("\n── FAILURES ──────────────────────────────────────────────────\n")
      any_fail = true
    end
    io.write(string.format("FAIL  %-30s  %s\n", r.route, r.label))
    if r.detail ~= "" then
      io.write(string.format("      detail: %s\n", r.detail))
    end
  end
end

-- Print all results
io.write("\n── FULL RESULTS ──────────────────────────────────────────────\n")
for _, r in ipairs(results) do
  local marker = r.outcome == "PASS" and "." or (r.outcome == "FAIL" and "F" or "S")
  io.write(string.format("%s  %-30s  %s\n", marker, r.route, r.label))
  if r.outcome ~= "PASS" and r.detail ~= "" then
    io.write(string.format("   %s\n", r.detail))
  end
end

io.write(string.format(
  "\n[%s] %d routes — %d passed  %d failed  %d skipped  (%d total cases)\n",
  app_name, #app.routes, pass_count, fail_count, skip_count, total))

if fail_count > 0 then os.exit(1) end

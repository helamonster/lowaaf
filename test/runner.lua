-- test/runner.lua
-- Run as:  resty -I /etc/openresty test/runner.lua [app-name]
--
-- Enumerates every route in the app and runs:
--   1.  Valid request        → expect WAF to allow
--   1b. Valid value variants → enum exhaustion, boolean true/false, number
--                              min/max, nullable absent/set → expect WAF to allow
--   2.  Wrong method         → expect WAF to deny
--   3.  Body-schema invalids (per-field boundary tests) → expect WAF to deny
--   4.  Form-schema invalids → expect WAF to deny
--   5.  Query-schema invalids → expect WAF to deny
--
-- A route is skipped (not failed) when no valid body can be auto-generated
-- (e.g. jwt_claims in query params).

-- package.path is provided by:  resty -I rootfs/etc/openresty test/runner.lua

local cjson = require "cjson.safe"

-- When WAF_HTTP_BASE is set the runner sends real HTTP requests to the live
-- Docker stack instead of exercising core.run() in-process.
local HTTP_BASE = os.getenv("WAF_HTTP_BASE")
local mock, http_client, core

if HTTP_BASE then
  http_client = require "test.http_client"
else
  -- mock_ngx must be required BEFORE waf.core so the global `ngx` is replaced
  -- before core.lua captures it via `local ngx = ngx`.
  mock = require "test.mock_ngx"
end

local gen = require "test.gen"

if not HTTP_BASE then
  core = require "waf.core"
end

-- Memoize gen.valid_values / gen.invalid_values so both the planning pass and
-- the execution pass get cached results — each schema is only walked once.
do
  local vv_cache = {}
  local iv_cache = {}
  local orig_vv  = gen.valid_values
  local orig_iv  = gen.invalid_values
  gen.valid_values   = function(v) if not vv_cache[v] then vv_cache[v] = orig_vv(v)  end return vv_cache[v] end
  gen.invalid_values = function(v) if not iv_cache[v] then iv_cache[v] = orig_iv(v)  end return iv_cache[v] end
end

-- ── Load app ──────────────────────────────────────────────────────────────────

local app_name = arg and arg[1] or "vaultwarden"
local ok, app = pcall(require, "waf.apps." .. app_name)
if not ok then
  io.stderr:write("Cannot load waf.apps." .. app_name .. ": " .. tostring(app) .. "\n")
  os.exit(1)
end

-- Force block mode so denied requests exit early (cleaner detection).
-- In HTTP mode the WAF runs in Docker; block mode is enabled there via the
-- /tmp/waf-block-mode sentinel file (managed by the online-test-full command).
local saved_mode = app.mode
if not HTTP_BASE then
  app.mode = "block"
end

-- ── Test infrastructure ───────────────────────────────────────────────────────

local pass_count   = 0
local fail_count   = 0
local skip_count   = 0
local results      = {}
local route_test_n = 0   -- per-route counter, reset at start of each test_route
local route_buf    = {}  -- per-route print buffer, flushed live after each route

local Y  = "\027[33m"   -- yellow
local G  = "\027[32m"   -- green
local R  = "\027[31m"   -- red
local RS = "\027[0m"    -- reset

-- Column widths: defaults overwritten after the planning pass.
local overall_fmt = "%5d"
local route_fmt   = "%3d"

-- When true: record() just counts and run_request() skips the WAF.
-- Used in the planning pass to determine column widths cheaply.
local planning = false

local function record(route_name, label, outcome, detail)
  route_test_n = route_test_n + 1
  if planning then return end
  results[#results+1] = {
    route   = route_name,
    label   = label,
    outcome = outcome,
    detail  = detail or "",
    route_n = route_test_n,
  }
  if outcome == "PASS" then
    pass_count = pass_count + 1
  elseif outcome == "FAIL" then
    fail_count = fail_count + 1
  else
    skip_count = skip_count + 1
  end
  route_buf[#route_buf+1] = {
    label     = label,
    outcome   = outcome,
    overall_n = #results,
    route_n   = route_test_n,
  }
end

local DESC_WIDTH = 80

local function fmt_desc(s)
  if #s <= DESC_WIDTH then
    return s .. string.rep(" ", DESC_WIDTH - #s)
  end
  return s:sub(1, DESC_WIDTH - 3) .. "..."
end

local function flush_route(route_name)
  for _, r in ipairs(route_buf) do
    local mark = r.outcome == "PASS" and (G .. "✓" .. RS)
              or r.outcome == "FAIL" and (R .. "✗" .. RS)
              or                        (Y .. "~" .. RS)
    io.write(string.format(
      "%s" .. overall_fmt .. "%s. %-30s  test #%s" .. route_fmt .. "%s  %s  %s\n",
      Y, r.overall_n, RS, route_name, Y, r.route_n, RS, fmt_desc(r.label), mark
    ))
  end
  if #route_buf > 0 then io.flush() end
  route_buf = {}
end

-- Run the WAF against req; return true if WAF allowed it, false if denied.
-- Returns true immediately during the planning pass (no WAF calls).
local function run_request(req)
  if planning then return true end

  if HTTP_BASE then
    local status = http_client.request(HTTP_BASE, req)
    if status == -1 then
      error("HTTP request to " .. HTTP_BASE .. " failed (is the Docker stack up?)")
    end
    -- -2: WAF set X-WAF: block (deny in block mode);  anything else: WAF passed
    return status ~= -2
  end

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
  route_test_n = 0
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
    if query_schema then
      local qv = gen.valid_value(query_schema)
      if qv ~= nil then valid_query = qv end
    end
    local allowed = run_request({
      method  = method,
      uri     = uri,
      headers = base_headers,
      query   = valid_query,
    })
    if allowed then
      record(name, "valid " .. method .. " " .. uri, "PASS")
    else
      record(name, "valid " .. method .. " " .. uri, "FAIL",
             "valid request was denied")
    end
  end

  -- ── 1b. Valid value variants ────────────────────────────────────────────────
  -- For each schema, test the full breadth of the valid surface: enum
  -- exhaustion, boolean true+false, number min+max, nullable absent/set.
  -- Section 1 already tested index 1 (the base), so we start at index 2.

  if json_schema then
    local all_schemas = route.json_schemas or { json_schema }
    for si, schema in ipairs(all_schemas) do
      local sfx      = (#all_schemas > 1) and (" (schema " .. si .. ")") or ""
      local variants = gen.valid_values(schema)
      for vi = 2, #variants do
        local pair     = variants[vi]
        local body_str = encode_body(pair.value)
        if body_str then
          local allowed = run_request({
            method  = method,
            uri     = uri,
            headers = base_headers,
            body    = body_str,
          })
          local label = "valid variant: " .. pair.label .. sfx
          if allowed then
            record(name, label, "PASS")
          else
            record(name, label, "FAIL", "valid variant was denied")
          end
        end
      end
    end

  elseif form_schema then
    local variants = gen.valid_values(form_schema)
    for vi = 2, #variants do
      local pair = variants[vi]
      if type(pair.value) == "table" then
        local allowed = run_request({
          method  = method,
          uri     = uri,
          headers = base_headers,
          form    = pair.value,
        })
        local label = "valid variant: " .. pair.label
        if allowed then
          record(name, label, "PASS")
        else
          record(name, label, "FAIL", "valid variant was denied")
        end
      end
    end
  end

  if query_schema then
    local variants = gen.valid_values(query_schema)
    for vi = 2, #variants do
      local pair = variants[vi]
      if type(pair.value) == "table" then
        -- Routes with both a body and query schema (e.g. ciphers purge) need
        -- the valid body present or the WAF denies at the body-validation step.
        local req = { method=method, uri=uri, headers=base_headers, query=pair.value }
        if valid_body then req.body = valid_body end
        if valid_form then req.form = valid_form end
        local allowed = run_request(req)
        local label = "valid query variant: " .. pair.label
        if allowed then
          record(name, label, "PASS")
        else
          record(name, label, "FAIL", "valid query variant was denied")
        end
      end
    end
  end

  -- ── 1c. Header valid variants ───────────────────────────────────────────────
  -- Test all confirmed-valid variants of every header validator (enum exhaustion,
  -- uuid alternatives, etc.).  Uses the same valid body/form from section 1 so
  -- body validation does not block these tests.

  do
    local merged = {}
    if app.defaults and app.defaults.headers then
      for k, v in pairs(app.defaults.headers) do merged[k] = v end
    end
    if route.headers then
      for k, v in pairs(route.headers) do merged[k] = v end
    end
    for header_name, validator in pairs(merged) do
      if type(validator) == "function" then
        for _, pair in ipairs(gen.valid_values(validator)) do
          if type(pair.value) == "string" then
            local hdrs = {}
            for k, v in pairs(base_headers) do hdrs[k] = v end
            hdrs[header_name] = pair.value
            local req = { method=method, uri=uri, headers=hdrs }
            if valid_body  then req.body  = valid_body  end
            if valid_form  then req.form  = valid_form  end
            if valid_query then req.query = valid_query end
            local allowed = run_request(req)
            local label = "valid header: " .. header_name .. "=" .. pair.label
            if allowed then
              record(name, label, "PASS")
            else
              record(name, label, "FAIL", "valid header variant was denied")
            end
          end
        end
      end
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

  -- ── 3b. Header value invalids ──────────────────────────────────────────────
  -- Merge app defaults + route headers, then send requests with each invalid value.

  do
    local merged = {}
    if app.defaults and app.defaults.headers then
      for k, v in pairs(app.defaults.headers) do merged[k] = v end
    end
    if route.headers then
      for k, v in pairs(route.headers) do merged[k] = v end
    end
    for header_name, validator in pairs(merged) do
      if type(validator) == "function" then
        for _, pair in ipairs(gen.invalid_values(validator)) do
          -- HTTP headers are always strings; non-string invalids become valid
          -- after core.lua's tostring() conversion, so skip them here.
          if type(pair.value) ~= "string" then goto continue end
          -- Null bytes are stripped by the HTTP parser before reaching the WAF.
          if HTTP_BASE and pair.value:find("\0", 1, true) then goto continue end
          local bad_hdrs = {}
          for k, v in pairs(base_headers) do bad_hdrs[k] = v end
          bad_hdrs[header_name] = pair.value
          local denied = not run_request({
            method  = method,
            uri     = uri,
            headers = bad_hdrs,
          })
          local label = "header " .. header_name .. " invalid: " .. pair.label
          if denied then
            record(name, label, "PASS")
          else
            record(name, label, "FAIL", "expected deny for invalid header value")
          end
          ::continue::
        end
      end
    end
  end

  -- ── 4. IP allowlist ────────────────────────────────────────────────────────
  -- (offline only: real HTTP cannot spoof remote_addr)

  if route.allow_ips and not HTTP_BASE then
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
  -- (offline only: sending max_body+1 bytes over HTTP is impractical)

  local max_body = route.max_body or (app.defaults and app.defaults.max_body)
  if max_body and not route.no_body and not HTTP_BASE then
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

  -- ── 8b. Malformed / wrong-type form body ──────────────────────────────────
  -- core.lua passes get_post_args() directly to validate_any_schema; if it
  -- returns a non-table the schema rejects it.  Section 10 skips non-table
  -- invalids, so test the structural cases here explicitly.
  -- (offline only: non-table values cannot be represented in a real HTTP body)

  if form_schema and not route.no_body and not HTTP_BASE then
    local bad_forms = {
      { form = "not a table", label = "string instead of form data" },
      { form = 123,           label = "number instead of form data" },
      { form = true,          label = "boolean instead of form data" },
    }
    for _, case in ipairs(bad_forms) do
      local denied = not run_request({
        method  = method,
        uri     = uri,
        headers = base_headers,
        form    = case.form,
      })
      if denied then
        record(name, "malformed form: " .. case.label, "PASS")
      else
        record(name, "malformed form: " .. case.label, "FAIL",
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
        -- In HTTP mode: URL-encoding converts all primitive values to strings, so
        -- type-mismatch invalids (boolean/number in a string field) become valid
        -- after form encoding.  Skip them; they are covered by the offline test.
        if HTTP_BASE then
          local type_mismatch = false
          for _, v in pairs(pair.value) do
            if type(v) == "boolean" or type(v) == "number" then
              type_mismatch = true; break
            end
          end
          if type_mismatch then goto next_form_invalid end
        end
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
        ::next_form_invalid::
      end
    end
  end

  -- ── 11. Query invalids ──────────────────────────────────────────────────────

  if query_schema then
    local invalids = gen.invalid_values(query_schema)
    for _, pair in ipairs(invalids) do
      if type(pair.value) == "table" then
        -- In HTTP mode: URL-encoded query params are always strings, so
        -- boolean/number type-mismatch invalids become valid after encoding.
        if HTTP_BASE then
          local type_mismatch = false
          for _, v in pairs(pair.value) do
            if type(v) == "boolean" or type(v) == "number" then
              type_mismatch = true; break
            end
          end
          if type_mismatch then goto next_query_invalid end
        end
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
        ::next_query_invalid::
      end
    end
  end
end

-- ── Run all routes ────────────────────────────────────────────────────────────

-- Planning pass: run test_route with the WAF disabled to count tests per route
-- and compute column widths.  gen.* results are memoized for the execution pass.
io.write(string.format("[%s] Planning...\n", app_name))
io.flush()

planning = true
local planned_total = 0
local max_per_route = 0
for _, route in ipairs(app.routes) do
  route_test_n = 0
  pcall(test_route, route)
  if route_test_n > max_per_route then max_per_route = route_test_n end
  planned_total = planned_total + route_test_n
end
planning = false

overall_fmt = string.format("%%%dd", #tostring(planned_total))
route_fmt   = string.format("%%%dd", #tostring(max_per_route))

-- Execution pass: run tests live, printing each route's results immediately.
io.write(string.format("[%s] Running %d tests...\n", app_name, planned_total))
io.flush()

for _, route in ipairs(app.routes) do
  route_test_n = 0
  route_buf    = {}
  local ok, err = pcall(test_route, route)
  if not ok then
    record(route.name or "?", "ERROR", "FAIL", tostring(err))
  end
  flush_route(route.name or "?")
end

if not HTTP_BASE then app.mode = saved_mode end

-- ── Summary ───────────────────────────────────────────────────────────────────

local total = pass_count + fail_count + skip_count

if fail_count > 0 then
  io.write("\n── FAILURES ──────────────────────────────────────────────────\n")
  for _, r in ipairs(results) do
    if r.outcome == "FAIL" then
      io.write(string.format("%sFAIL%s  %-30s  %s\n", R, RS, r.route, r.label))
      if r.detail ~= "" then io.write(string.format("      %s\n", r.detail)) end
    end
  end
end

io.write(string.format(
  "\n[%s] %d routes — %d passed  %d failed  %d skipped  (%d total cases)\n",
  app_name, #app.routes, pass_count, fail_count, skip_count, total))

if fail_count > 0 then os.exit(1) end

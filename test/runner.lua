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

-- Route-level concurrency (HTTP mode only - see below). Off by default logic
-- doesn't apply here since default is ON; WAF_TEST_PARALLEL=0 disables it.
-- Offline/mock mode can't be parallelized: mock.set_request()/core.run(app)
-- both read and mutate shared global mock state, so concurrent routes would
-- corrupt each other's requests.
local PARALLEL_ENABLED = (os.getenv("WAF_TEST_PARALLEL") or "1") ~= "0"
local PARALLEL_N        = tonumber(os.getenv("WAF_TEST_PARALLEL_N")) or 16

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

-- Positive-test enhancement (online mode only): log in for real so "valid
-- variant" requests carry a genuine authenticated session/token, not just
-- anonymous requests with synthetic-but-schema-valid field values. This
-- only verifies the WAF doesn't block an authenticated request shape -
-- whether the app itself then succeeds/permits the action is out of scope
-- here. Never fatal: a login failure just means the rest of the run
-- proceeds anonymous, same as before. Each app has a completely different
-- auth mechanism: mediawiki and jellyfin need their own login modules
-- (test/mw_login.lua, test/jellyfin_login.lua); gitea (plain HTTP Basic)
-- and vaultwarden (shells out to docker/vaultwarden/register.js, which
-- already implements Bitwarden's real client-side crypto) are simple/
-- subprocess-based enough to just inline here.
local EXTRA_AUTH_HEADER   -- { name = "...", value = "..." } or nil
if HTTP_BASE then
  if app_name == "mediawiki" then
    local mw_login = require "test.mw_login"
    local mw_user = os.getenv("MW_ADMIN_USER") or "Admin"
    local mw_pass = os.getenv("MW_ADMIN_PASS") or "WafTestPass123!"
    local cookie, err = mw_login.login(HTTP_BASE, mw_user, mw_pass)
    if cookie then
      EXTRA_AUTH_HEADER = { name = "Cookie", value = cookie }
      io.write(string.format("[%s] Logged in as %s for positive tests.\n", app_name, mw_user))
    else
      io.write(string.format(
        "[%s] Could not log in as %s (continuing anonymous): %s\n", app_name, mw_user, tostring(err)))
    end

  elseif app_name == "gitea" then
    -- Gitea's REST API accepts HTTP Basic directly - no subprocess, no
    -- separate login module needed. Same admin account tools.sh's
    -- docker-test-up already provisions (`gitea admin user create`).
    local gt_user = os.getenv("GITEA_ADMIN_USER") or "Admin"
    local gt_pass = os.getenv("GITEA_ADMIN_PASS") or "WafTestPass123!"
    EXTRA_AUTH_HEADER = {
      -- Lowercase, matching gitea.lua's own declared key (`["authorization"]
      -- = gitea_auth_header`) exactly - base_headers/bad_headers are plain
      -- Lua tables, so a differently-cased "Authorization" here would sit
      -- alongside that key as a second entry instead of overwriting it,
      -- and http_client.lua sends both as separate header lines (confirmed
      -- live: this exact mismatch let the WAF see the still-valid value
      -- underneath every "header authorization invalid" fuzz case, turning
      -- ~5000 expected-deny tests into false passes).
      name  = "authorization",
      value = "Basic " .. ngx.encode_base64(gt_user .. ":" .. gt_pass),
    }
    io.write(string.format("[%s] Using HTTP Basic auth as %s for positive tests.\n", app_name, gt_user))

  elseif app_name == "jellyfin" then
    local jellyfin_login = require "test.jellyfin_login"
    local jf_user = os.getenv("JELLYFIN_ADMIN_USER") or "wafuser"
    local jf_pass = os.getenv("JELLYFIN_ADMIN_PASS") or "WafTestPass123!"
    local header, err = jellyfin_login.login(HTTP_BASE, jf_user, jf_pass)
    if header then
      -- Lowercase - see the gitea branch above for why this matters even
      -- though jellyfin.lua doesn't currently value-fuzz this header itself.
      EXTRA_AUTH_HEADER = { name = "authorization", value = header }
      io.write(string.format("[%s] Logged in as %s for positive tests.\n", app_name, jf_user))
    else
      io.write(string.format(
        "[%s] Could not log in as %s (continuing anonymous): %s\n", app_name, jf_user, tostring(err)))
    end

  elseif app_name == "vaultwarden" then
    -- Defaults MUST match docker/vaultwarden/register.js's own BW_EMAIL/
    -- BW_PASSWORD defaults (also bw_test_live.sh's, which relies on the
    -- same defaults) - not some other app's admin-cred convention. This
    -- account is registered once and reused across runs (see
    -- BW_TOLERATE_EXISTING below), so a mismatched default here doesn't
    -- fail loudly - it silently logs in with the wrong password against an
    -- account that already exists under register.js's password, and falls
    -- back to anonymous testing (confirmed live: this exact mismatch was
    -- the actual bug the first time this branch was written).
    local vw_email = os.getenv("VW_TEST_EMAIL")    or "waftest@example.com"
    local vw_pass  = os.getenv("VW_TEST_PASSWORD") or "WafTest1234!"
    local register_js = "docker/vaultwarden/register.js"
    local cmd = string.format(
      "BW_EMAIL=%q BW_PASSWORD=%q BW_SERVER=%q BW_TOLERATE_EXISTING=1 node %q 2>/tmp/waf_vw_login_err",
      vw_email, vw_pass, HTTP_BASE, register_js)
    local p = io.popen(cmd)
    local out = p and p:read("*a") or ""
    local closed = p and p:close()
    local token = out:match("(%S+)%s*$")   -- last non-blank line, per register.js's contract
    if closed and token and #token > 0 then
      -- Lowercase - see the gitea branch above; vaultwarden.lua declares
      -- this same key (`["authorization"] = vw_auth_header`) lowercase too.
      EXTRA_AUTH_HEADER = { name = "authorization", value = "Bearer " .. token }
      io.write(string.format("[%s] Logged in as %s for positive tests.\n", app_name, vw_email))
    else
      local errf = io.open("/tmp/waf_vw_login_err", "r")
      local errtext = errf and errf:read("*a") or ""
      if errf then errf:close() end
      io.write(string.format(
        "[%s] Could not log in as %s (continuing anonymous): %s\n", app_name, vw_email, errtext))
    end
    os.remove("/tmp/waf_vw_login_err")
  end
  io.flush()
end

-- ── Test infrastructure ───────────────────────────────────────────────────────

local pass_count   = 0
local fail_count   = 0
local skip_count   = 0
local results      = {}

-- pass_count/fail_count/skip_count/results are shared across routes, but the
-- increments/inserts below never yield mid-operation, so they stay safe even
-- when multiple routes' test_route() calls are running concurrently as
-- separate light threads (cooperative scheduling: only I/O calls like
-- run_request() yield). route_test_n and the print buffer, in contrast, are
-- per-route state - each test_route() call gets its OWN local copies (via
-- make_recorder() below) instead of sharing one global, or concurrent routes
-- would stomp on each other's counters and interleave print buffers.

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

local DESC_WIDTH = 80

local function fmt_desc(s)
  if #s <= DESC_WIDTH then
    return s .. string.rep(" ", DESC_WIDTH - #s)
  end
  return s:sub(1, DESC_WIDTH - 3) .. "..."
end

-- Builds a fresh record()/flush_route() pair with their own private
-- route_test_n/print-buffer state, for one test_route() call to use.
local function make_recorder()
  local route_test_n = 0
  local route_buf    = {}

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

  return record, flush_route, function() return route_test_n end
end

-- A query table this large, urlencoded onto a real GET request line, exceeds
-- nginx's own URI-length limit (~8KB by default) and gets rejected with a
-- plain 414 before the WAF ever runs - not a realistic request shape any
-- real client would send. Routes with pathologically wide merged schemas
-- (api.php's union of every action's + every query submodule's fields, incl.
-- the g-prefixed generator= variants, is 1200+ fields) build their "valid"
-- test fixture by setting every possible field at once, the same "wider than
-- reality" fixture that already needed an offline-only skip for arg-count
-- reasons (FORM_ARG_CAP/QUERY_ARG_CAP below) - HTTP mode needs this
-- additional, separate skip for total BYTE LENGTH, which is a different
-- constraint (a small field count can still produce a huge byte length, and
-- vice versa). Confirmed live: api.php's full valid fixture is ~16KB.
local QUERY_HTTP_BYTE_CAP = 8000
local function query_too_big_for_http(q)
  if not HTTP_BASE or type(q) ~= "table" then return false end
  local total = 0
  for k, v in pairs(q) do
    total = total + #tostring(k) + #tostring(v) + 2
  end
  return total > QUERY_HTTP_BYTE_CAP
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
  -- HEAD rides on GET's permission in core.lua (both the global method
  -- check and route matching treat it as GET) - it's only genuinely
  -- rejected if GET itself would be, for this route or globally.
  local head_effectively_ok = allowed["GET"] or global_ok["GET"]
  -- 1. Try PATCH / HEAD / TRACE — blocked globally, no shared-URI ambiguity.
  for _, m in ipairs({ "PATCH", "HEAD", "TRACE" }) do
    if m == "HEAD" then
      if not head_effectively_ok then return m end
    elseif not allowed[m] and not global_ok[m] then
      return m
    end
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

-- ── multipart/form-data body serialization ────────────────────────────────────
-- The offline mock bypasses real body encoding for "form" fields (get_post_args
-- just hands back the Lua table directly), which exercises schema-validation
-- logic but never the real byte-level multipart parser in core.lua. Routes with
-- a multipart content-type get one additional real-encoded request (see below)
-- so that parser gets genuine end-to-end coverage, not just the mock bypass.
local MULTIPART_BOUNDARY = "----waftestboundary1234567890"

local function encode_multipart(fields)
  local parts = {}
  for k, v in pairs(fields) do
    if type(v) == "string" then
      parts[#parts+1] = "--" .. MULTIPART_BOUNDARY .. "\r\n"
        .. 'Content-Disposition: form-data; name="' .. k .. '"\r\n\r\n'
        .. v .. "\r\n"
    end
  end
  parts[#parts+1] = "--" .. MULTIPART_BOUNDARY .. "--\r\n"
  return table.concat(parts)
end

local function is_multipart_route(route)
  local ct = route.content_types or route.content_type
  for _, v in ipairs(type(ct) == "table" and ct or { ct }) do
    if v == "multipart/form-data" then return true end
  end
  return false
end

-- ── Per-route test runner ─────────────────────────────────────────────────────

local function test_route(route)
  local record, flush_route, get_route_test_n = make_recorder()
  local name    = route.name or "?"
  local uri     = gen.route_uri(route)
  local methods = route_methods(route)
  if #methods == 0 then
    record(name, "no methods defined", "SKIP")
    flush_route(name)
    return get_route_test_n()
  end
  local method = methods[1]

  -- Determine what headers are needed for this route.
  local base_headers = {
    ["User-Agent"]  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " ..
                      "AppleWebKit/537.36 (KHTML, like Gecko) " ..
                      "Chrome/120.0 Safari/537.36 Bitwarden/2026.5.0",
  }
  if EXTRA_AUTH_HEADER then
    -- A route can override the app-default validator for this exact header
    -- (e.g. vaultwarden's "public org import" requires a distinct org-API-key
    -- bearer JWT instead of the standard user-login one) - confirmed live:
    -- attaching the logged-in user's token there anyway doesn't test "a
    -- logged-in user hits this route", it just sends the wrong credential
    -- type and gets correctly denied, which isn't a false positive to fix,
    -- it's the WAF working - so skip the global header for routes with
    -- their own override and let them go anonymous, matching pre-login
    -- behavior. Section 1c below still separately exercises the route's own
    -- validator with its own synthetic-valid values, so that route's real
    -- auth requirement remains covered.
    local overridden = route.headers and route.headers[EXTRA_AUTH_HEADER.name]
    if not overridden then
      base_headers[EXTRA_AUTH_HEADER.name] = EXTRA_AUTH_HEADER.value
    end
  end
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

  -- Routes can declare a query schema alongside a body schema (e.g. cipher
  -- import-organization's required ?organizationId=). Compute valid_query up
  -- front so every branch below (and the variant/header tests further down,
  -- which already expect valid_query to be populated) can attach it.
  if query_schema then
    local qv = gen.valid_value(query_schema)
    if qv ~= nil then valid_query = qv end
  end

  if json_schema then
    local v = gen.valid_value(json_schema)
    if v == nil then
      record(name, "valid request", "SKIP", "cannot auto-gen JSON body")
    else
      valid_body = encode_body(v)
      if not valid_body then
        record(name, "valid request", "SKIP", "body not JSON-encodable")
      else
        local req = {
          method  = method,
          uri     = uri,
          headers = base_headers,
          body    = valid_body,
        }
        if valid_query then req.query = valid_query end
        local allowed = run_request(req)
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
            local req2 = { method=method, uri=uri, headers=base_headers, body=ab }
            if valid_query then req2.query = valid_query end
            local ok = run_request(req2)
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
      local req = {
        method  = method,
        uri     = uri,
        headers = base_headers,
        form    = valid_form,
      }
      if valid_query then req.query = valid_query end
      local allowed = run_request(req)
      if allowed then
        record(name, "valid " .. method .. " " .. uri, "PASS")
      else
        record(name, "valid " .. method .. " " .. uri, "FAIL",
               "valid request was denied")
      end

      if is_multipart_route(route) then
        local mp_headers = {}
        for k, hv in pairs(base_headers) do mp_headers[k] = hv end
        mp_headers["Content-Type"] = "multipart/form-data; boundary=" .. MULTIPART_BOUNDARY

        local mp_allowed = run_request({
          method  = method,
          uri     = uri,
          headers = mp_headers,
          body    = encode_multipart(valid_form),
        })
        if mp_allowed then
          record(name, "valid multipart-encoded " .. method .. " " .. uri, "PASS")
        else
          record(name, "valid multipart-encoded " .. method .. " " .. uri, "FAIL",
                 "valid multipart-encoded request was denied")
        end

        local bad_fields = {}
        for k, fv in pairs(valid_form) do bad_fields[k] = fv end
        bad_fields["__unexpected_field__"] = "x"
        local mp_denied = not run_request({
          method  = method,
          uri     = uri,
          headers = mp_headers,
          body    = encode_multipart(bad_fields),
        })
        if mp_denied then
          record(name, "multipart unexpected field rejected", "PASS")
        else
          record(name, "multipart unexpected field rejected", "FAIL",
                 "unexpected multipart field was allowed")
        end
      end
    end
  else
    -- No body schema: valid request has no body; valid_query (computed above,
    -- if the route declares a query schema) is included below.
    if query_too_big_for_http(valid_query) then
      record(name, "valid " .. method .. " " .. uri, "SKIP",
             "full valid query fixture exceeds a realistic URI length over real HTTP")
    else
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
          local req = {
            method  = method,
            uri     = uri,
            headers = base_headers,
            body    = body_str,
          }
          if valid_query then req.query = valid_query end
          local allowed = run_request(req)
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
        local req = {
          method  = method,
          uri     = uri,
          headers = base_headers,
          form    = pair.value,
        }
        if valid_query then req.query = valid_query end
        local allowed = run_request(req)
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
        local label = "valid query variant: " .. pair.label
        if query_too_big_for_http(pair.value) then
          record(name, label, "SKIP", "full valid query fixture exceeds a realistic URI length over real HTTP")
        else
          -- Routes with both a body and query schema (e.g. ciphers purge) need
          -- the valid body present or the WAF denies at the body-validation step.
          local req = { method=method, uri=uri, headers=base_headers, query=pair.value }
          if valid_body then req.body = valid_body end
          if valid_form then req.form = valid_form end
          local allowed = run_request(req)
          if allowed then
            record(name, label, "PASS")
          else
            record(name, label, "FAIL", "valid query variant was denied")
          end
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
            local label = "valid header: " .. header_name .. "=" .. pair.label
            if query_too_big_for_http(valid_query) then
              record(name, label, "SKIP", "full valid query fixture exceeds a realistic URI length over real HTTP")
            else
              local hdrs = {}
              for k, v in pairs(base_headers) do hdrs[k] = v end
              hdrs[header_name] = pair.value
              local req = { method=method, uri=uri, headers=hdrs }
              if valid_body  then req.body  = valid_body  end
              if valid_form  then req.form  = valid_form  end
              if valid_query then req.query = valid_query end
              local allowed = run_request(req)
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
      -- A genuinely nullable top-level body schema (T.nullable(T.object(...)),
      -- matching a real `[FromBody] SomeDto?` signature that defaults
      -- server-side when omitted) legitimately accepts a literal JSON
      -- `null` body - that's valid input there, not malformed.
      if case.body == "null" and gen.is_nullable(json_schema) then
        record(name, "malformed json: " .. case.label, "SKIP", "schema is nullable - null is valid input")
        goto continue_bad_body
      end
      do
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
      ::continue_bad_body::
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
    -- core.lua caps form parsing at ngx.req.get_post_args(200): a route whose
    -- merged schema has more than 200 possible keys (api.php's union of every
    -- action's + every query submodule's fields, currently 700+) can produce
    -- a "base valid object covering every field at once" test fixture wider
    -- than that cap. Offline mode hands the Lua table straight to the
    -- validator and never parses a real form body, so it's unaffected; over
    -- real HTTP, nginx's own arg-count truncation can silently drop the one
    -- deliberately-invalid field before the WAF ever sees it - a real client
    -- sending 200+ distinct field names in one POST isn't a realistic shape
    -- this route needs to defend against, so - like max_body+1 above - this
    -- is offline-only.
    local FORM_ARG_CAP = 200
    for _, pair in ipairs(invalids) do
      if type(pair.value) == "table" and HTTP_BASE then
        local n = 0
        for _ in pairs(pair.value) do n = n + 1 end
        if n > FORM_ARG_CAP then goto next_form_invalid end
      end
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
      end
      ::next_form_invalid::
    end
  end

  -- ── 11. Query invalids ──────────────────────────────────────────────────────

  if query_schema then
    local invalids = gen.invalid_values(query_schema)
    -- Same story as the form-invalid cap above, but for GET: core.lua caps
    -- query parsing at ngx.req.get_uri_args(100), and api.php's merged
    -- schema is well beyond that. Offline-only for the same reason.
    local QUERY_ARG_CAP = 100
    for _, pair in ipairs(invalids) do
      if type(pair.value) == "table" and HTTP_BASE then
        local n = 0
        for _ in pairs(pair.value) do n = n + 1 end
        if n > QUERY_ARG_CAP then goto next_query_invalid end
      end
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
      end
      ::next_query_invalid::
    end
  end

  flush_route(name)
  return get_route_test_n()
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
  local ok, n = pcall(test_route, route)
  local route_n = ok and n or 0
  if route_n > max_per_route then max_per_route = route_n end
  planned_total = planned_total + route_n
end
planning = false

overall_fmt = string.format("%%%dd", #tostring(planned_total))
route_fmt   = string.format("%%%dd", #tostring(max_per_route))

-- Execution pass: run tests live. Sequentially, each route's results print
-- as a contiguous block immediately after it finishes (original behavior).
-- Concurrently (HTTP mode, default on - see PARALLEL_ENABLED above), routes
-- still each print as one contiguous block (per-route buffering is exactly
-- what make_recorder() exists for) but blocks appear in whichever order
-- their route happens to finish in, not app.routes order - every line is
-- still self-labeled with its route name, so this doesn't lose information,
-- just reorders it.
io.write(string.format("[%s] Running %d tests...\n", app_name, planned_total))
io.flush()

local function run_one_route(route)
  local ok, err = pcall(test_route, route)
  if not ok then
    results[#results+1] = {
      route = route.name or "?", label = "ERROR", outcome = "FAIL",
      detail = tostring(err), route_n = 1,
    }
    fail_count = fail_count + 1
    io.write(string.format("%sFAIL%s  %-30s  ERROR: %s\n", R, RS, route.name or "?", tostring(err)))
    io.flush()
  end
end

if HTTP_BASE and PARALLEL_ENABLED and PARALLEL_N > 1 then
  local n_routes = #app.routes
  local next_idx = 0
  local function worker()
    while true do
      next_idx = next_idx + 1
      if next_idx > n_routes then return end
      run_one_route(app.routes[next_idx])
    end
  end
  local n_workers = math.min(PARALLEL_N, n_routes)
  local threads = {}
  for i = 1, n_workers do
    threads[i] = ngx.thread.spawn(worker)
  end
  for i = 1, n_workers do
    ngx.thread.wait(threads[i])
  end
else
  for _, route in ipairs(app.routes) do
    run_one_route(route)
  end
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

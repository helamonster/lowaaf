-- test/jellyfin_login.lua
-- One-time first-run-wizard bootstrap + real AuthenticateByName login for the
-- jellyfin online test, so "valid variant" requests carry a genuine
-- Authorization: MediaBrowser ... token instead of always being anonymous.
-- Only used when WAF_HTTP_BASE is set (online mode) and the app under test
-- is jellyfin.
--
-- A fresh Jellyfin container has no users until its Startup wizard
-- completes - confirmed live:
--   1. GET /System/Info/Public -> StartupWizardCompleted bool (idempotency
--      check: skip the bootstrap entirely once true - re-running it after
--      completion 401s).
--   2. GET /Startup/User -> {"Name":"root"} (Jellyfin auto-creates a default
--      user pre-wizard; [Authorize(Policy = FirstTimeSetupOrElevated)] only
--      allows this unauthenticated before the wizard completes).
--   3. POST /Startup/User {"Name":..,"Password":..} -> 204.
--   4. POST /Startup/Complete -> 204.
-- Steps 1-4 must bypass the WAF-fronted port: jellyfin.lua has no route for
-- /Startup/* at all (correct - real production traffic never needs it,
-- deny-by-default), so hitting it through the WAF 403s. Since curl exists
-- inside the jellyfin container, these go via `docker exec jellyfin curl
-- http://localhost:8096/...` (the container's own internal port), exactly
-- mirroring how gitea's admin user is provisioned via `docker exec gitea
-- gitea admin user create` rather than HTTP through the WAF.
--
-- Step 5 (the real login) goes THROUGH the WAF (`base`, e.g.
-- http://localhost:8892) - this is real traffic the WAF should see. It
-- requires an Authorization: MediaBrowser ... header even for the login
-- call itself (confirmed live: without it, real Jellyfin 400s with "Error
-- processing request").
--
-- Shells out to curl throughout (like test/mw_login.lua) rather than
-- hand-rolling this on the raw cosocket client in http_client.lua (which
-- deliberately never reads response bodies - it only checks the WAF's
-- X-WAF header): this only runs once per test run, so correctness/
-- simplicity wins over avoiding a subprocess.

local cjson = require "cjson.safe"

local M = {}

local JELLYFIN_CONTAINER = os.getenv("JELLYFIN_CONTAINER") or "jellyfin"
local CLIENT_ID = "waf-test-device-0000-000000000001"

local function shell(cmd)
  local p = io.popen(cmd .. " 2>&1")
  local out = p:read("*a")
  local ok = p:close()
  return out, ok
end

-- One `docker exec jellyfin curl ...` call against the container's own
-- internal port (8096) - bypasses the WAF entirely, see file header.
local function exec_curl(args)
  return shell("docker exec " .. JELLYFIN_CONTAINER .. " curl -sS -o /dev/null -w '%{http_code}' " .. args)
end

local function auth_header(token)
  local h = string.format(
    'MediaBrowser Client="waf-test", Device="waf-test", DeviceId="%s", Version="10.11.11"', CLIENT_ID)
  if token then h = h .. string.format(', Token="%s"', token) end
  return h
end

--- Bootstraps the Jellyfin first-run wizard (if not already done) and logs
--- in as `username`/`password` against `base` (e.g. http://localhost:8892).
--- Returns a full Authorization header VALUE string on success, or nil +
--- reason on failure. Never throws: a login failure should degrade to
--- anonymous testing, not abort the run.
function M.login(base, username, password)
  -- 1. Idempotency check.
  local info_json, ok0 = shell(string.format(
    "docker exec %s curl -sS http://localhost:8096/System/Info/Public", JELLYFIN_CONTAINER))
  if not ok0 then
    return nil, "could not reach jellyfin container to check wizard status: " .. tostring(info_json)
  end
  local info = cjson.decode(info_json)
  local wizard_done = info and info.StartupWizardCompleted

  if not wizard_done then
    -- 2. Confirm the pre-wizard default user exists (formality/idempotency
    --    check, mirrors the confirmed-live flow - result isn't used).
    exec_curl("http://localhost:8096/Startup/User")

    -- 3. Create the real test user.
    local user_body = cjson.encode({ Name = username, Password = password })
    local code3, ok3 = exec_curl(string.format(
      "-X POST -H 'Content-Type: application/json' -d %q http://localhost:8096/Startup/User",
      user_body))
    if not ok3 or code3 ~= "204" then
      return nil, "Startup/User POST failed (HTTP " .. tostring(code3) .. "): " .. tostring(user_body)
    end

    -- 4. Complete the wizard.
    local code4, ok4 = exec_curl("-X POST http://localhost:8096/Startup/Complete")
    if not ok4 or code4 ~= "204" then
      return nil, "Startup/Complete POST failed (HTTP " .. tostring(code4) .. ")"
    end
  end

  -- 5. Real login, through the WAF.
  local login_body = cjson.encode({ Username = username, Pw = password })
  local login_json, ok5 = shell(string.format(
    "curl -sS -X POST -H %q -H 'Content-Type: application/json' -d %q %q",
    "Authorization: " .. auth_header(nil), login_body, base .. "/Users/AuthenticateByName"))
  if not ok5 then
    return nil, "AuthenticateByName request failed: " .. tostring(login_json)
  end
  local login_result = cjson.decode(login_json)
  local token = login_result and login_result.AccessToken
  if not token then
    return nil, "no AccessToken in response: " .. tostring(login_json)
  end

  return auth_header(token)
end

return M

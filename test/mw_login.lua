-- test/mw_login.lua
-- One-time AuthManager clientlogin handshake for the mediawiki online test,
-- so "valid variant" requests carry a real logged-in session (session
-- cookies, not just synthetic schema-valid field values) instead of always
-- being anonymous. Only used when WAF_HTTP_BASE is set (online mode) and the
-- app under test is mediawiki - there's no real backend to log into offline,
-- and other apps have their own login flows (or none needed) already.
--
-- Shells out to curl rather than hand-rolling chunked-transfer decoding on
-- top of the raw cosocket client in http_client.lua: this only runs once per
-- test run (not the hot path), so correctness/simplicity wins over avoiding
-- a subprocess.

local cjson = require "cjson.safe"

local M = {}

local function shell(cmd)
  local p = io.popen(cmd .. " 2>&1")
  local out = p:read("*a")
  local ok = p:close()
  return out, ok
end

-- Builds a `Cookie: a=1; b=2` header string from a curl Netscape cookie jar.
local function cookie_header_from_jar(jar_path)
  local f = io.open(jar_path, "r")
  if not f then return nil end
  local pairs_ = {}
  for line in f:lines() do
    -- curl marks HttpOnly cookies with a "#HttpOnly_" prefix on the domain
    -- field - that's real cookie data, not a comment, despite starting with
    -- "#" (MediaWiki's session cookies are all HttpOnly, so skipping these
    -- like ordinary "# comment" lines silently drops every cookie that
    -- actually matters).
    if line ~= "" and (not line:match("^#") or line:match("^#HttpOnly_")) then
      -- domain, flag, path, secure, expiry, name, value (tab-separated)
      local name, value = line:match("[^\t]+\t[^\t]+\t[^\t]+\t[^\t]+\t[^\t]+\t([^\t]+)\t([^\t\r\n]+)")
      if name then
        pairs_[#pairs_ + 1] = name .. "=" .. value
      end
    end
  end
  f:close()
  if #pairs_ == 0 then return nil end
  return table.concat(pairs_, "; ")
end

--- Logs in as `username`/`password` against `base` (e.g. http://localhost:8889).
--- Returns a Cookie header string on success, or nil + reason on failure.
--- Never throws: a login failure should degrade to anonymous testing, not
--- abort the run.
function M.login(base, username, password)
  local jar = os.tmpname()

  local token_json, ok1 = shell(string.format(
    "curl -sS -c %q -b %q %q",
    jar, jar, base .. "/api.php?action=query&meta=tokens&type=login&format=json"
  ))
  if not ok1 then
    os.remove(jar)
    return nil, "could not reach " .. base .. " to fetch a login token: " .. tostring(token_json)
  end

  local decoded = cjson.decode(token_json)
  local token = decoded and decoded.query and decoded.query.tokens and decoded.query.tokens.logintoken
  if not token then
    os.remove(jar)
    return nil, "no logintoken in response: " .. tostring(token_json)
  end

  local login_json, ok2 = shell(string.format(
    "curl -sS -c %q -b %q " ..
    "--data-urlencode %q --data-urlencode %q --data-urlencode %q " ..
    "--data-urlencode %q --data-urlencode %q --data-urlencode %q %q",
    jar, jar,
    "action=clientlogin",
    "username=" .. username,
    "password=" .. password,
    "loginreturnurl=" .. base .. "/",
    "logintoken=" .. token,
    "format=json",
    base .. "/api.php"
  ))
  if not ok2 then
    os.remove(jar)
    return nil, "clientlogin request failed: " .. tostring(login_json)
  end

  local login_result = cjson.decode(login_json)
  local status = login_result and login_result.clientlogin and login_result.clientlogin.status
  if status ~= "PASS" then
    os.remove(jar)
    return nil, "clientlogin did not PASS: " .. tostring(login_json)
  end

  local cookie_header = cookie_header_from_jar(jar)
  os.remove(jar)
  if not cookie_header then
    return nil, "clientlogin PASSed but no cookies were set"
  end
  return cookie_header
end

return M

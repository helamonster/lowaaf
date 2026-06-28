-- test/mock_ngx.lua
-- Replaces the global `ngx` with a plain Lua table before any waf.* module
-- is loaded.  types.lua captures `local ngx = ngx` at require time, so this
-- file must be required FIRST in the runner (before waf.core / waf.types).
--
-- Real ngx.re, ngx.null, ngx.decode_base64 are preserved so validators work.

-- Capture the fields we need from the real ngx before we replace it.
local real_re            = ngx.re
local real_null          = ngx.null
local real_decode_base64 = ngx.decode_base64
local real_encode_base64 = ngx.encode_base64
local real_WARN          = ngx.WARN
local real_INFO          = ngx.INFO

-- ── Shared mutable state (modified by set_request on each test call) ──────────

local _req    = {}
local _denied = false
local _EXIT   = {}   -- unique sentinel; pcall checks for this table identity

-- ── Build the replacement ngx table ──────────────────────────────────────────

local mock_ngx = {
  -- Preserved from real ngx (pure functions, no request context needed)
  re            = real_re,
  null          = real_null,
  decode_base64 = real_decode_base64,
  encode_base64 = real_encode_base64,
  WARN          = real_WARN,
  INFO          = real_INFO,
  time          = function() return os.time() end,

  -- Per-request context; reset by set_request()
  ctx    = { waf_verbose = 0, waf_log_mode = true },
  status = 200,

  req = {
    get_method    = function()   return _req.method or "GET" end,
    read_body     = function()   end,
    get_body_data = function()   return _req.body end,
    get_post_args = function(_)  return _req.form or {} end,
    get_headers   = function(_)
      -- nginx normalizes header names to lowercase; replicate that here
      local raw = _req.headers or {}
      local normalized = {}
      for k, v in pairs(raw) do normalized[k:lower()] = v end
      return normalized
    end,
    get_uri_args  = function(_)  return _req.query or {} end,
  },

  var = setmetatable({}, {
    __index = function(_, k)
      if k == "uri"                  then return _req.uri or "/" end
      if k == "remote_addr"          then return _req.remote_addr or "127.0.0.1" end
      if k == "server_name"          then return _req.server_name or "test.local" end
      if k == "http_content_length"  then
        if _req.content_length then return tostring(_req.content_length) end
        if _req.body then return tostring(#_req.body) end
        return "0"
      end
      return nil
    end,
    __newindex = function() end,
  }),

  -- Any WARN-level log means deny() was called.
  log = function(level, ...)
    if level == real_WARN then _denied = true end
  end,

  say   = function() end,
  -- timer.at used by core.ipset_deny_hook; no-op in tests (we don't call ipset)
  timer = { at = function() end },

  -- In block mode, deny() calls ngx.exit() after logging.
  -- Throw the sentinel so core.run() aborts; runner catches it via pcall.
  exit = function(status)
    _denied = true
    error(_EXIT)
  end,
}

-- Replace the global ngx.  All waf.* modules required after this point will
-- capture this table via their `local ngx = ngx` declarations.
ngx = mock_ngx

-- ── Public API ────────────────────────────────────────────────────────────────

local mock = {}
mock._EXIT = _EXIT

function mock.set_request(t)
  _req    = t or {}
  _denied = false
  mock_ngx.ctx    = { waf_verbose = 0, waf_log_mode = true }
  mock_ngx.status = 200
end

function mock.was_denied()
  return _denied
end

return mock

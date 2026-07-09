-- test/http_client.lua
-- Minimal HTTP(S) client using OpenResty cosockets for online-test-full.
-- Only reads response headers + drains the body (needed to safely reuse a
-- keepalive connection); the body content itself is never inspected. Used as
-- a drop-in replacement for mock_ngx.run_request() when WAF_HTTP_BASE is set:
-- the WAF runs live in the Docker container, so we check the HTTP response
-- code instead of inspecting the mock deny flag.

local M = {}

-- WAF_TEST_KEEPALIVE=0 forces a fresh TCP (+TLS) connection per request, i.e.
-- the original behavior. Default on: reusing connections from OpenResty's
-- built-in per-worker cosocket pool cuts out a full connect (+handshake) per
-- request, which otherwise dominates wall-clock time over tens of thousands
-- of test cases.
local KEEPALIVE_ENABLED     = (os.getenv("WAF_TEST_KEEPALIVE") or "1") ~= "0"
local KEEPALIVE_TIMEOUT_MS  = tonumber(os.getenv("WAF_TEST_KEEPALIVE_TIMEOUT_MS")) or 60000
-- Should be >= the runner's concurrency (WAF_TEST_PARALLEL_N) or workers will
-- end up fighting over a too-small pool and closing connections early.
local KEEPALIVE_POOL_SIZE   = tonumber(os.getenv("WAF_TEST_KEEPALIVE_POOL_SIZE")) or 64

-- Parse "https://host:port" or "http://host:port".  Port defaults to 443/80.
local function parse_base(base)
  local scheme, host, port_str = base:match("^(https?)://([^:/]+):?(%d*)$")
  if not scheme then
    error("WAF_HTTP_BASE must be https://host:port or http://host, got: " .. base)
  end
  local port = tonumber(port_str)
  if not port then port = scheme == "https" and 443 or 80 end
  return scheme, host, port
end

local function url_encode(s)
  return tostring(s):gsub("[^%w%-%.%_%~]", function(c)
    return string.format("%%%02X", string.byte(c))
  end)
end

local function kv_encode(t)
  local parts = {}
  for k, v in pairs(t) do
    parts[#parts + 1] = url_encode(k) .. "=" .. url_encode(v)
  end
  table.sort(parts)   -- stable order
  return table.concat(parts, "&")
end

-- One connect+send+receive attempt. Returns (status, reused) on success,
-- (nil, reused) on any I/O failure - `reused` tells the caller whether it's
-- worth retrying once on a guaranteed-fresh connection (a pooled keepalive
-- connection can go stale between being returned to the pool and being
-- picked back up - e.g. the server's own keepalive timeout racing ours).
local function try_once(scheme, host, port, raw, want_keepalive, want_body_drain)
  local sock = ngx.socket.tcp()
  sock:settimeout(5000)
  local ok = sock:connect(host, port)
  if not ok then
    sock:close()
    return nil, false
  end
  local reused = sock:getreusedtimes() > 0

  if scheme == "https" then
    local sess = sock:sslhandshake(nil, host, false)
    if not sess then
      sock:close()
      return nil, reused
    end
  end

  local _, send_err = sock:send(raw)
  if send_err then
    sock:close()
    return nil, reused
  end

  local line = sock:receive("*l")
  if not line then
    sock:close()
    return nil, reused
  end
  local status = tonumber(line:match("HTTP/%S+ (%d+)"))
  if not status then
    sock:close()
    return nil, reused
  end

  -- Read the rest of the headers; look for X-WAF: block (added by core.lua
  -- on deny) and whatever's needed to safely drain/reuse the connection.
  local waf_blocked = false
  local resp_length, chunked, server_close = nil, false, not want_keepalive
  while true do
    local hdr = sock:receive("*l")
    if not hdr or hdr == "" or hdr == "\r" then break end
    local lhdr = hdr:lower()
    if lhdr:match("^x%-waf:%s*block") then
      waf_blocked = true
    elseif not resp_length then
      local cl = lhdr:match("^content%-length:%s*(%d+)")
      if cl then resp_length = tonumber(cl) end
    end
    if lhdr:match("^transfer%-encoding:%s*chunked") then
      chunked = true
    elseif lhdr:match("^connection:%s*close") then
      server_close = true
    end
  end

  -- Drain the body so the socket is safe to hand back to the pool. HEAD
  -- responses never have a body regardless of what the headers claim.
  local drain_ok = true
  if want_body_drain then
    if chunked then
      while true do
        local size_line = sock:receive("*l")
        if not size_line then drain_ok = false; break end
        local size = tonumber(size_line:match("^(%x+)"), 16)
        if not size then drain_ok = false; break end
        if size == 0 then
          sock:receive("*l")  -- trailer end CRLF
          break
        end
        if not sock:receive(size) then drain_ok = false; break end
        sock:receive(2)  -- CRLF after chunk data
      end
    elseif resp_length and resp_length > 0 then
      if not sock:receive(resp_length) then drain_ok = false end
    end
  end

  if want_keepalive and drain_ok and not server_close then
    sock:setkeepalive(KEEPALIVE_TIMEOUT_MS, KEEPALIVE_POOL_SIZE)
  else
    sock:close()
  end

  local final = (waf_blocked or status == 413) and -2 or status
  return final, reused
end

-- Sends one HTTP/1.1 request and returns the numeric response status, or
-- -1 on connection/read failure (caller maps this to an error).
function M.request(base, req)
  local scheme, host, port = parse_base(base)

  local method = req.method or "GET"
  local uri    = req.uri    or "/"

  -- query string
  if req.query and next(req.query) then
    uri = uri .. "?" .. kv_encode(req.query)
  end

  -- body
  local body = ""
  if type(req.body) == "string" then
    body = req.body
  elseif type(req.form) == "table" then
    body = kv_encode(req.form)
  end

  -- Content-Length: honour an explicit override (e.g. max_body+1 test);
  -- otherwise use the actual body length.
  local content_length = req.content_length or #body

  -- request headers
  local hdr_lines = "Host: " .. host .. ":" .. tostring(port) .. "\r\n"
                 .. "Connection: " .. (KEEPALIVE_ENABLED and "keep-alive" or "close") .. "\r\n"
                 .. "Content-Length: " .. tostring(content_length) .. "\r\n"
  local req_headers = req.headers or {}
  for k, v in pairs(req_headers) do
    hdr_lines = hdr_lines .. k .. ": " .. tostring(v) .. "\r\n"
  end

  local raw = method .. " " .. uri .. " HTTP/1.1\r\n"
           .. hdr_lines .. "\r\n"
           .. body

  local want_body_drain = method ~= "HEAD"

  local status, reused = try_once(scheme, host, port, raw, KEEPALIVE_ENABLED, want_body_drain)
  if status == nil and reused then
    -- Stale pooled connection - retry once with whatever connection we get
    -- next (usually fresh, since the stale one was just closed above).
    status = (try_once(scheme, host, port, raw, KEEPALIVE_ENABLED, want_body_drain))
  end
  return status or -1
end

return M

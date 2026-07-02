-- test/http_client.lua
-- Minimal HTTPS client using OpenResty cosockets for online-test-full.
-- Only reads the response status line (Connection: close); no body parsing.
-- Used as a drop-in replacement for mock_ngx.run_request() when WAF_HTTP_BASE
-- is set: the WAF runs live in the Docker container, so we check the HTTP
-- response code instead of inspecting the mock deny flag.

local M = {}

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
                 .. "Connection: close\r\n"
                 .. "Content-Length: " .. tostring(content_length) .. "\r\n"
  local req_headers = req.headers or {}
  for k, v in pairs(req_headers) do
    hdr_lines = hdr_lines .. k .. ": " .. tostring(v) .. "\r\n"
  end

  local raw = method .. " " .. uri .. " HTTP/1.1\r\n"
           .. hdr_lines .. "\r\n"
           .. body

  -- connect
  local sock = ngx.socket.tcp()
  sock:settimeout(5000)
  local ok, err = sock:connect(host, port)
  if not ok then
    sock:close()
    return -1
  end

  if scheme == "https" then
    local sess
    sess, err = sock:sslhandshake(nil, host, false)
    if not sess then
      sock:close()
      return -1
    end
  end

  -- send
  local _, send_err = sock:send(raw)
  if send_err then
    sock:close()
    return -1
  end

  -- read status line
  local line
  line, err = sock:receive("*l")
  if not line then sock:close(); return -1 end
  local status = tonumber(line:match("HTTP/%S+ (%d+)"))
  if not status then sock:close(); return -1 end

  -- read remaining headers; look for X-WAF: block (added by core.lua on deny)
  local waf_blocked = false
  while true do
    local hdr = sock:receive("*l")
    if not hdr or hdr == "" or hdr == "\r" then break end
    if hdr:lower():match("^x%-waf:%s*block") then
      waf_blocked = true
    end
  end
  sock:close()

  -- A WAF block is signalled by the X-WAF: block header (added by core.lua on deny).
  -- 413 (Request Entity Too Large) is nginx rejecting the body before the WAF runs;
  -- it is still a rejection, semantically equivalent to a WAF max_body denial.
  return (waf_blocked or status == 413) and -2 or status
end

return M

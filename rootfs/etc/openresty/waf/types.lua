local ngx = ngx
local T = {}

local function fail(msg)
  return false, msg
end

function T.string(opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "string" then return fail(path .. " must be a string") end
    if opts.min and #v < opts.min then
      return fail(path .. " too short (min " .. opts.min .. ")")
    end
    if opts.max and #v > opts.max then
      return fail(path .. " too long (max " .. opts.max .. ")")
    end
    if opts.match and not ngx.re.find(v, opts.match, "jo") then
      return fail(path .. " invalid format")
    end
    if opts.not_match and ngx.re.find(v, opts.not_match, "jo") then
      return fail(path .. " contains forbidden characters")
    end
    if opts.enum and not opts.enum[v] then
      return fail(path .. " invalid value")
    end
    return true
  end
end

function T.number(opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "number" then return fail(path .. " must be a number") end
    if opts.integer and v % 1 ~= 0 then
      return fail(path .. " must be an integer")
    end
    if opts.min and v < opts.min then
      return fail(path .. " too small (min " .. opts.min .. ")")
    end
    if opts.max and v > opts.max then
      return fail(path .. " too large (max " .. opts.max .. ")")
    end
    return true
  end
end

function T.boolean()
  return function(v, path)
    if type(v) ~= "boolean" then return fail(path .. " must be a boolean") end
    return true
  end
end

function T.uuid()
  return T.string({
    match = [[^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$]]
  })
end

function T.email()
  return T.string({
    min       = 3,
    max       = 320,
    match     = [[^[^@\s]+@[^@\s]+\.[^@\s]+$]],
    not_match = "[\\x00-\\x1f\\x7f<>\"]",
  })
end

-- passes if value is JSON null or Lua nil, otherwise delegates to inner
function T.nullable(inner)
  return function(v, path)
    if v == ngx.null or v == nil then return true end
    return inner(v, path)
  end
end

function T.array(inner, opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "table" then return fail(path .. " must be an array") end
    local n = #v
    if opts.min and n < opts.min then
      return fail(path .. " array too short (min " .. opts.min .. ")")
    end
    if opts.max and n > opts.max then
      return fail(path .. " array too long (max " .. opts.max .. ")")
    end
    for i = 1, n do
      local ok, err = inner(v[i], path .. "[" .. i .. "]")
      if not ok then return false, err end
    end
    return true
  end
end

-- schema: { key = validator, ... }
-- opts.required: { key = true, ... } for mandatory keys
-- unknown keys are always rejected
function T.object(schema, opts)
  opts = opts or {}
  return function(v, path)
    if type(v) ~= "table" then return fail(path .. " must be an object") end
    for key, _ in pairs(v) do
      if not schema[key] then
        return fail(path .. "." .. tostring(key) .. " is not an allowed key")
      end
    end
    for key, validator in pairs(schema) do
      local value = v[key]
      if value ~= nil then
        local ok, err = validator(value, path .. "." .. key)
        if not ok then return false, err end
      elseif opts.required and opts.required[key] then
        return fail(path .. "." .. key .. " is required")
      end
    end
    return true
  end
end

return T

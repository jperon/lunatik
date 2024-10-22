local iter
local wrap
wrap = function(self)
  local _ = {
    __call = self,
    __index = iter
  }
  return setmetatable(_, _)
end
iter = {
  __call = function(self, t)
    local i = 0
    return wrap(function()
      i = i + 1
      return t[i]
    end)
  end,
  each = function(self, fn)
    while true do
      do
        local v = self()
        if v then
          fn(v)
        else
          break
        end
      end
    end
  end,
  map = function(self, fn)
    return wrap(function()
      do
        local v = self()
        if v then
          return fn(v)
        end
      end
    end)
  end,
  imap = function(self, fn)
    local i = 0
    return wrap(function()
      do
        local v = self()
        if v then
          i = i + 1
          return fn(v, i)
        end
      end
    end)
  end,
  filter = function(self, fn)
    return wrap(function()
      while true do
        do
          local v = self()
          if v then
            if fn(v) then
              return v
            end
          else
            return 
          end
        end
      end
    end)
  end,
  take = function(self, n)
    local i = 0
    return wrap(function()
      i = i + 1
      if i <= n then
        return self()
      end
    end)
  end,
  toarray = function(self)
    local t = { }
    while true do
      do
        local v = self()
        if v then
          t[#t + 1] = v
        else
          break
        end
      end
    end
    return t
  end,
  reduce = function(self, fn, initial)
    local accum = initial or self()
    for v in self do
      accum = fn(accum, v)
    end
    return accum
  end
}
iter.__index = iter
setmetatable(iter, iter)
local imap
imap = function(self, fn)
  return iter(self):map(fn)
end
local map
map = function(self, fn)
  return iter(self):map(fn)
end
local filter
filter = function(self, fn)
  return iter(self):filter(fn)
end
local take
take = function(self, n)
  return iter(self):take(n)
end
local reduce
reduce = function(self, ...)
  return iter(self):reduce(...)
end
local generate
generate = function(fn)
  return wrap(function()
    return fn()
  end)
end
local range
range = function(self, max, step)
  step = step or 1
  local i = max and self - step or 0
  max = max or self
  return wrap(function()
    i = i + step
    if i <= max then
      return i
    end
  end)
end
return {
  iter = iter,
  wrap = wrap,
  imap = imap,
  map = map,
  filter = filter,
  take = take,
  reduce = reduce,
  generate = generate,
  range = range
}

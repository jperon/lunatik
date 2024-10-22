local concat, insert, remove = table.concat, table.insert, table.remove
local range, wrap
do
  local _ = require("ipparse.fun")
  range, wrap = _.range, _.wrap
end
local Net, Net4, Net6
do
  local __tostring
  __tostring = function(self)
    return concat(range(4):map(function(i)
      return self[i]
    end):toarray(), ".") .. "/" .. tostring(self.mask)
  end
  local mt = {
    __index = function(self, k)
      return self.bits >> 8 * (4 - k) & (1 << 8) - 1
    end,
    __le = function(self, o)
      if type(self) == "string" then
        self = Net(self)
      end
      if type(o) == "string" then
        o = Net(o)
      end
      return o.v == self.v and o.mask <= self.mask and (self.bits >> (32 - o.mask) << (32 - o.mask)) == o.bits
    end,
    __tostring = __tostring,
    __repr = __tostring
  }
  Net4 = function(self)
    local mask
    self, mask = self:match("([^/]*)/?([^/]*)$")
    mask = tonumber(mask) or 32
    local bits = wrap(self:gmatch("[^%.]+")):imap(function(self, i)
      return tonumber(self) << 8 * (4 - i)
    end):reduce(function(a, b)
      return a + b
    end)
    bits = bits >> (32 - mask) << (32 - mask)
    return setmetatable({
      bits = bits,
      mask = mask,
      v = 4
    }, mt)
  end
end
do
  local __repr
  __repr = function(self)
    local s = concat(range(8):map(function(i)
      return ("%x"):format(self[i])
    end):toarray(), ":")
    for n = 8, 1, -1 do
      local zeros = ":" .. concat(range(n):map(function()
        return "0"
      end):toarray(), ":")
      local r
      s, r = s:gsub(zeros, "::", 1)
      if r > 0 then
        s = s:gsub(":::*", "::"):gsub("^0::", "::"):gsub("^::0$", "::")
        break
      end
    end
    return tostring(s) .. "/" .. tostring(self.mask)
  end
  local mt = {
    __index = function(self, k)
      return self.bits[(k - 1) // 4 + 1] >> 16 * ((8 - k) % 4) & (1 << 16) - 1
    end,
    __le = function(self, o)
      if type(self) == "string" then
        self = Net(self)
      end
      if type(o) == "string" then
        o = Net(o)
      end
      if o.v ~= self.v or o.mask > self.mask then
        return false
      end
      if o.mask >= 64 and self.bits[1] ~= o.bits[1] then
        return false
      end
      if o.mask < 64 and (self.bits[1] >> (64 - o.mask) << (64 - o.mask)) ~= o.bits[1] then
        return false
      end
      return (self.bits[2] >> (128 - o.mask) << (128 - o.mask)) == o.bits[2]
    end,
    __tostring = __repr,
    __repr = __repr
  }
  Net6 = function(self)
    local mask
    self, mask = self:match("([^/]*)/?([^/]*)$")
    mask = tonumber(mask) or 128
    local address = wrap(self:gmatch("([^:]*):?")):toarray()
    local zeros = 9 - #address
    for i = 1, 8 do
      local part = address[i]
      if part == "" and zeros then
        for _ = 1, zeros do
          insert(address, i, 0)
          i = i + 1
        end
        zeros = 1
        remove(address, i)
      else
        address[i] = type(part) == "string" and tonumber(part, 16) or part
      end
    end
    local bits = { }
    for i = 1, #address do
      local k = (i - 1) // 4 + 1
      bits[k] = bits[k] or 0
      bits[k] = bits[k] + (address[i] << 16 * ((8 - i) % 4))
    end
    if mask < 64 then
      bits[1] = bits[1] >> (64 - mask) << (64 - mask)
    end
    bits[2] = bits[2] >> (128 - mask) << (128 - mask)
    return setmetatable({
      bits = bits,
      mask = mask,
      v = 6
    }, mt)
  end
end
Net = function(self)
  return self:match(":") and Net6(self) or Net4(self)
end
return {
  Net = Net,
  Net4 = Net4,
  Net6 = Net6
}

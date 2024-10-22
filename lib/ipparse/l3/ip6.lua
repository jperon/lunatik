local subclass = require("ipparse").subclass
local IP = require("ipparse.l3.ip")
local range = require("ipparse.fun").range
local concat
concat = table.concat
return subclass(IP, {
  __name = "IP6",
  get_ip_at = function(self, off)
    return concat(range(off, off + 14, 2):map(function(i)
      return ("%x"):format(self:short(i))
    end):toarray(), ":")
  end,
  is_fragment = function() end,
  _get_length = function(self)
    return self.data_off + self:short(4)
  end,
  _get_next_header = function(self)
    return self:byte(6)
  end,
  _get_protocol = function(self)
    return self.next_header
  end,
  _get_src = function(self)
    return self:get_ip_at(8)
  end,
  _get_dst = function(self)
    return self:get_ip_at(24)
  end,
  data_off = 40
})

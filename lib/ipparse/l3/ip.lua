local subclass, Packet
do
  local _ = require("ipparse")
  subclass, Packet = _.subclass, _.Packet
end
local bidirectional
bidirectional = function(self)
  for k, v in pairs(self) do
    self[v] = k
  end
  return self
end
return subclass(Packet, {
  __name = "IP",
  _get_version = function(self)
    return self:nibble(0)
  end,
  protocols = bidirectional({
    TCP = 0x06,
    UDP = 0x11,
    GRE = 0x2F,
    ESP = 0x32,
    ICMPv6 = 0x3A,
    OSPF = 0x59
  })
})

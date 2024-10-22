local subclass, Packet
do
  local _ = require("ipparse")
  subclass, Packet = _.subclass, _.Packet
end
return subclass(Packet, {
  __name = "UDP",
  protocol_type = 0x11,
  _get_sport = function(self)
    return self:short(0)
  end,
  _get_dport = function(self)
    return self:short(2)
  end,
  _get_length = function(self)
    return self:short(4)
  end,
  _get_checksum = function(self)
    return self:short(6)
  end,
  data_off = 8
})

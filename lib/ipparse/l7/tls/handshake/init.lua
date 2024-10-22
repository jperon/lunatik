local subclass, Packet
do
  local _ = require("ipparse")
  subclass, Packet = _.subclass, _.Packet
end
return subclass(Packet, {
  __name = "TLSHandshake",
  record_type = 0x16,
  _get_type = function(self)
    return self:byte(0)
  end,
  _get_length = function(self)
    return self:byte(1) << 16 | self:short(2)
  end,
  data_off = 4
})

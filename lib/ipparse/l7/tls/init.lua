local subclass, Packet
do
  local _ = require("ipparse")
  subclass, Packet = _.subclass, _.Packet
end
return subclass(Packet, {
  __name = "TLS",
  iana_port = 443,
  _get_type = function(self)
    return self:byte(0)
  end,
  _get_version = function(self)
    return tostring(self:byte(1)) .. "." .. tostring(self:byte(2))
  end,
  _get_length = function(self)
    return self:short(3)
  end,
  data_off = 5
})

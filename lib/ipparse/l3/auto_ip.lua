local IP = require("ipparse.l3.ip")
local IPn = {
  [4] = require("ipparse.l3.ip4"),
  [6] = require("ipparse.l3.ip6")
}
return function(self)
  do
    local ip = IPn[IP(self).version]
    if ip then
      return ip(self)
    end
  end
end

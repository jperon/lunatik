local subclass, Packet
do
  local _ = require("ipparse")
  subclass, Packet = _.subclass, _.Packet
end
local range, wrap
do
  local _ = require("ipparse.fun")
  range, wrap = _.range, _.wrap
end
local TLSExtension = require("ipparse.l7.tls.handshake.extension")
local min = math.min
local co_wrap, co_yield = coroutine.wrap, coroutine.yield
local TLS_extensions = {
  [0x00] = require("ipparse.l7.tls.handshake.extension.server_name")
}
setmetatable(TLS_extensions, {
  __index = function(self, extension_type)
    return subclass(TLSExtension, {
      __name = "UnknownTlsExtension",
      extension_type = extension_type,
      type_str = "unknown"
    })
  end
})
return subclass(Packet, {
  __name = "TLSClientHello",
  message_type = 0x01,
  _get_client_version = function(self)
    return tostring(self:byte(0)) .. "." .. tostring(self:byte(1))
  end,
  _get_client_random = function(self)
    return self:str(2, 32)
  end,
  _get_session_id_length = function(self)
    return self:byte(34)
  end,
  _get_session_id = function(self)
    return self:str(35, self.session_id_length)
  end,
  _get_ciphers_offset = function(self)
    return 35 + self.session_id_length
  end,
  _get_ciphers_length = function(self)
    return self:short(self.ciphers_offset)
  end,
  _get_ciphers = function(self)
    return range(0, self.ciphers_lenght - 2, 2):map(function(i)
      return self:short(self.ciphers_offset + 2 + i)
    end):toarray()
  end,
  _get_compressions_offset = function(self)
    return self.ciphers_offset + 2 + self.ciphers_length
  end,
  _get_compressions_length = function(self)
    return self:byte(self.compressions_offset)
  end,
  _get_compressions = function(self)
    return range(0, self.compressions_length - 1):map(function(i)
      return self:byte(self.compressions_offset + 1 + i)
    end):toarray()
  end,
  _get_extensions_offset = function(self)
    return self.compressions_offset + 1 + self.compressions_length
  end,
  _get_extensions = function(self)
    return wrap(self.iter_extensions):toarray()
  end,
  iter_extensions = function(self)
    return co_wrap(function()
      local offset = self.extensions_offset + 2
      local max_offset = min(#self.skb - self.off - 6, offset + self:short(self.extensions_offset))
      while offset < max_offset do
        local extension = TLS_extensions[self:short(offset)]({
          skb = self.skb,
          off = self.off + offset
        })
        co_yield(extension)
        offset = offset + extension.length
      end
    end)
  end
})

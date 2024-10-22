local subclass, Packet
do
  local _ = require("ipparse")
  subclass, Packet = _.subclass, _.Packet
end
local map = require("ipparse.fun").map
local concat = table.concat
return subclass(Packet, {
  __name = "DNSQuestion",
  _get_labels_offsets = function(self)
    local offsets = { }
    local pos = 0
    for _ = 1, 1000 do
      local size = self:byte(pos)
      if size == 0 then
        break
      end
      pos = pos + 1
      if size & 0xC0 == 0 then
        offsets[#offsets + 1] = {
          pos,
          size
        }
      else
        local off = ((size & 0x3F) << 8) + self:byte(pos)
        offsets[#offsets + 1] = {
          off + 1,
          self:byte(off)
        }
        break
      end
      pos = pos + size
    end
    return offsets
  end,
  _get_labels = function(self)
    local offs = self.labels_offsets
    return map(offs, function(lbl)
      local o, len, ptr = lbl[1], lbl[2], lbl[3]
      if len == 0 then
        for i = 1, #offs do
          local _lbl = offs[i]
          local _o, _len = _lbl[1], _lbl[2]
          if _o == ptr then
            o, len = _o, _len
            break
          end
        end
      end
      return self:str(o, len)
    end):toarray()
  end,
  _get_qtype_offset = function(self)
    local offs = self.labels_offsets
    local last = offs[#offs]
    return last[1] + last[2] + 1
  end,
  _get_qtype = function(self)
    return self:short(self.qtype_offset)
  end,
  _get_qclass = function(self)
    return self:short(self.qtype_offset + 2)
  end,
  _get_qname = function(self)
    return concat(self.labels, ".")
  end,
  _get_length = function(self)
    return self.qtype_offset + 4
  end
})

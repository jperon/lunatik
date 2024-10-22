local IP4 = require("ipparse.l3.ip4")
local data_new
data_new = require("data").new
local sort
sort = table.sort
local fragmented = { }
return {
  collect = function(self)
    local id = self.id
    local fragments = fragmented[id] or { }
    fragmented[id] = fragments
    local _skb, off, data_off, data_len, mf = self.skb, self.off, self.data_off, self.data_len, self.mf
    local frag_off = self.fragmentation_off << 3
    local total_len = off + frag_off + data_off + data_len
    local max_len = total_len > 10240 and 65535 or 10240
    if max_len > 65535 then
      return nil, "Invalid size"
    end
    local skb = fragments.skb
    if skb then
      if #skb < max_len then
        local tmp = data_new(max_len)
        for i = 0, #skb - 1 do
          tmp:setbyte(i, skb:getbyte(i))
        end
        skb = tmp
      end
    else
      skb = data_new(max_len)
    end
    fragments.skb = skb
    if frag_off == 0 then
      for i = 0, off + data_off + data_len - 1 do
        skb:setbyte(i, _skb:getbyte(i))
      end
    else
      local offset = off + data_off
      for i = offset, offset + data_len - 1 do
        skb:setbyte((frag_off + i), _skb:getbyte(i))
      end
    end
    fragments[#fragments + 1] = {
      frag_off = frag_off,
      off = off,
      data_off = data_off,
      data_len = data_len,
      mf = mf
    }
    sort(fragments, function(a, b)
      return a.frag_off < b.frag_off
    end)
    local lastfrag = fragments[#fragments]
    if lastfrag.mf ~= 0 then
      return 
    end
    off, frag_off, data_off, data_len = lastfrag.off, lastfrag.frag_off, lastfrag.data_off, lastfrag.data_len
    total_len = off + frag_off + data_off + data_len
    fragmented[id] = nil
    local ip = IP4({
      skb = skb,
      off = off
    })
    ip.__len = function()
      return total_len
    end
    return ip
  end
}

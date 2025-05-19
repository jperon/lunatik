-- Implements HKDF (RFC 5869) using the 'crypto' C module.
--
-- SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

local shash = require("crypto_shash")
local char, sp, rep, sub = string.char, string.pack, string.rep, string.sub


-- HKDF (RFC 5869)
return function (alg) -- e.g., alg = "sha256"
  alg = "hmac(" .. alg .. ")"
  local hmac_tfm = shash.new(alg)
  local hash_len = hmac_tfm:digestsize()  -- The digestsize of "hmac(alg)" is the same as "alg"
  local default_salt = rep("\0", hash_len)  -- default salt is zeros

  local function hmac(key, data)
    -- The key needs to be set before each HMAC operation if it changes,
    -- or if the TFM is used for other operations in between.
    -- For HKDF, the PRK is used as the key for multiple HMAC operations in expand.
    hmac_tfm:setkey(key)
    return hmac_tfm:digest(data) -- 'digest' is now a direct method of the TFM object
  end

  local function extract(salt, ikm)
    return hmac((salt or default_salt), ikm)
  end

  local function expand(prk, info, length)
    info = info or ""
    local n = length / hash_len  -- integer division, as we’re in Lunatik
    n = (n * hash_len == length) and n or n + 1
    if length == 0 then n = 0 end

    local okm, t = "", ""
    for i = 1, n do
      t = hmac(prk, t .. info .. char(i))
      okm = okm .. t
    end
    return sub(okm, 1, length)
  end

  local function hkdf(salt, ikm, info, length)
    return expand(extract(salt, ikm), info, length)
  end

  -- TLS 1.3 HKDF-Expand-Label (RFC 8446, Section 7.1)
  local function tls13_expand_label(prk, label, context, length)
    local hkdf_label_info = sp(">Hs1s1", length, "tls13 " .. label, context)
    return expand(prk, hkdf_label_info, length)
  end

  local instance_methods = {
    hkdf = hkdf,
    extract = extract,
    expand = expand,
    tls13_expand_label = tls13_expand_label,
    close = function()
      if hmac_tfm and hmac_tfm.__close then
        hmac_tfm:__close()
        hmac_tfm = nil
      end
    end
  }
  return setmetatable(instance_methods, { __gc = instance_methods.close })
end

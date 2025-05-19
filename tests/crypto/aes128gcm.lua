--
-- SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--
local util = require"util"
local bin2hex = util.bin2hex
local hex2bin = util.hex2bin

local test, expected, result

xpcall(
  function ()
		print"AEAD AES-128-GCM"
    local AeadCipher = require"crypto.aead"
    local c = AeadCipher.new"gcm(aes)"
    c:setkey"0123456789abcdef"
    c:setauthsize(16)

    test = "AES-128-GCM encrypt"
    expected = hex2bin"95be1ddc3dd13cdd2d8ffcc391561ade661d5b696ede5a918e"
    result = c:encrypt("abcdefghijkl", "plaintext", "0123456789abcdef")
    assert(result == expected)

    test = "AES-128-GCM decrypt"
    expected = "plaintext"
    result = c:decrypt("abcdefghijkl", result, "0123456789abcdef")
    assert(result == expected)

		print"All AEAD tests passed"
	end,

	function(msg)
		print("Test " .. test .. " FAILED")
		print("Result: " .. bin2hex(result))
		print("Expected: " .. bin2hex(expected))
		print(msg)
		print(debug.traceback())
	end
)


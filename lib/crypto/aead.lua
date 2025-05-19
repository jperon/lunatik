--
-- SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- @module crypto.aead

-- This module provides a Lua class wrapper for AEAD (Authenticated Encryption
-- with Associated Data) operations, using the underlying 'crypto_aead' C module

local aead = require("crypto_aead")
local sub = string.sub

local AeadCipher = {}
AeadCipher.__index = AeadCipher

--- Creates a new AEAD cipher instance.
-- @tparam string algname The algorithm name, e.g., "gcm(aes)".
-- @treturn AeadCipher self A new AeadCipher instance. Errors if C object creation fails.
function AeadCipher.new(algname)
	if type(algname) ~= "string" then
		error("AeadCipher.new: algname must be a string", 2)
	end

	return setmetatable({_tfm = aead.new(algname)}, AeadCipher)
end

--- Sets the key for the AEAD cipher.
-- @tparam string key The encryption key.
-- Propagates error from C on failure.
function AeadCipher:setkey(key)
	if type(key) ~= "string" then error("setkey: key must be a string", 2) end
	self._tfm:setkey(key)
end

--- Sets the authentication tag size for the AEAD cipher.
-- @tparam number tagsize The desired tag size in bytes.
-- Propagates error from C on failure.
function AeadCipher:setauthsize(tagsize)
	if type(tagsize) ~= "number" then error("setauthsize: tagsize must be a number", 2) end
	self._tfm:setauthsize(tagsize)
end

--- Encrypts plaintext.
-- @tparam string nonce The unique nonce (Number used once).
-- @tparam string plaintext The plaintext to encrypt.
-- @tparam[opt] string aad Additional Authenticated Data.
-- @treturn string ciphertext_with_tag The encrypted data including the authentication tag.
-- @treturn number tag_length The length of the authentication tag in bytes.
-- @return Propagates error from C on failure.
function AeadCipher:encrypt(nonce, plaintext, aad)
	if type(nonce) ~= "string" then error("encrypt: nonce must be a string", 2) end
	if type(plaintext) ~= "string" then error("encrypt: plaintext must be a string", 2) end
	if aad ~= nil and type(aad) ~= "string" then error("encrypt: AAD must be a string or nil", 2) end
	aad = aad or ""

	-- The C function self._tfm:encrypt returns (aad || ciphertext || tag).
	-- Extract (ciphertext || tag) from (aad || ciphertext || tag).
	return sub(self._tfm:encrypt(nonce, aad .. plaintext, #aad), #aad + 1), self._tfm:authsize()
end

--- Decrypts ciphertext.
-- @tparam string nonce The unique nonce (must match encryption).
-- @tparam string ciphertext_with_tag The ciphertext including the tag.
-- @tparam[opt] string aad Additional Authenticated Data (must match encryption).
-- @treturn string plaintext The decrypted data on success.
-- @return Propagates error from C on failure.
function AeadCipher:decrypt(nonce, ciphertext_with_tag, aad)
	if type(nonce) ~= "string" then error("decrypt: nonce must be a string", 2) end
	if type(ciphertext_with_tag) ~= "string" then error("decrypt: ciphertext_with_tag must be a string", 2) end
	if aad ~= nil and type(aad) ~= "string" then error("decrypt: AAD must be a string or nil", 2) end
	aad = aad or ""

	-- The C function self._tfm:decrypt returns (aad || plaintext)
	-- Extract plaintext from (aad || plaintext)
	return sub(self._tfm:decrypt(nonce, aad .. ciphertext_with_tag, #aad), #aad + 1)
end

--- Closes the cipher instance and releases underlying C resources.
-- If not called, the garbage collector will do its job.
function AeadCipher:__close()
	if self._tfm and self._tfm.__close then
		self._tfm:__close()
		self._tfm = nil
	end
end

AeadCipher.__gc = AeadCipher.__close

return AeadCipher
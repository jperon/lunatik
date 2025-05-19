/*
* SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <lunatik.h>

static const lunatik_class_t luacrypto_aead_tfm_class;
static const lunatik_class_t luacrypto_shash_tfm_class;

/* --- AEAD Transform (tfm) Userdata --- */
typedef struct {
	struct crypto_aead *tfm;
	struct aead_request *req; // Allocated with the TFM

	// Formerly in luacrypto_aead_request_t
	u8 *iv_data;
	size_t iv_len;

	u8 *work_buffer;
	size_t work_buffer_len; // Allocated size of work_buffer

	// These track lengths within work_buffer for the current operation
	size_t aad_len_in_buffer;
	size_t crypt_data_len_in_buffer; // For encrypt: PT len. For decrypt: CT+Tag len.

	struct scatterlist sg_work; // Scatterlist for work_buffer
} luacrypto_aead_tfm_t;

LUNATIK_PRIVATECHECKER(luacrypto_check_aead_tfm, luacrypto_aead_tfm_t *);

static void luacrypto_aead_tfm_release(void *private)
{
	luacrypto_aead_tfm_t *tfm_ud = (luacrypto_aead_tfm_t *)private;
	if (!tfm_ud) {
		return;
	}

	// Free resources formerly in luacrypto_aead_request_t
	kfree(tfm_ud->iv_data);
	tfm_ud->iv_data = NULL;
	kfree(tfm_ud->work_buffer);
	tfm_ud->work_buffer = NULL;

	if (tfm_ud->req) {
		aead_request_free(tfm_ud->req);
		tfm_ud->req = NULL;
	}

	if (tfm_ud->tfm && !IS_ERR(tfm_ud->tfm)) {
		crypto_free_aead(tfm_ud->tfm);
	}
}


/* --- AEAD TFM Methods --- */

static int luacrypto_aead_tfm_setkey(lua_State *L) {
	luacrypto_aead_tfm_t *tfm_ud = luacrypto_check_aead_tfm(L, 1);
	size_t keylen;
	const char *key = luaL_checklstring(L, 2, &keylen);
	int ret = crypto_aead_setkey(tfm_ud->tfm, key, keylen);
	if (ret) return luaL_error(L, "aead_tfm:setkey: failed (%d)", ret);
	return 0;
}

static int luacrypto_aead_tfm_setauthsize(lua_State *L) {
	luacrypto_aead_tfm_t *tfm_ud = luacrypto_check_aead_tfm(L, 1);
	unsigned int tagsize = luaL_checkinteger(L, 2);
	int ret = crypto_aead_setauthsize(tfm_ud->tfm, tagsize);
	if (ret) return luaL_error(L, "failed to set authsize (%d)", ret);
	return 0;
}

static int luacrypto_aead_tfm_ivsize(lua_State *L) {
	luacrypto_aead_tfm_t *tfm_ud = luacrypto_check_aead_tfm(L, 1);
	lua_pushinteger(L, crypto_aead_ivsize(tfm_ud->tfm));
	return 1;
}

static int luacrypto_aead_tfm_authsize(lua_State *L) {
	luacrypto_aead_tfm_t *tfm_ud = luacrypto_check_aead_tfm(L, 1);
	lua_pushinteger(L, crypto_aead_authsize(tfm_ud->tfm));
	return 1;
}

static int luacrypto_aead_tfm_encrypt(lua_State *L) {
	luacrypto_aead_tfm_t *tfm_ud = luacrypto_check_aead_tfm(L, 1);
	size_t iv_s_len, combined_s_len, aad_s_len, actual_data_s_len;
	const char *iv_s = luaL_checklstring(L, 2, &iv_s_len);
	const char *combined_s = luaL_checklstring(L, 3, &combined_s_len); // AAD || Plaintext
	lua_Integer aad_l = luaL_checkinteger(L, 4);
	int ret;
	unsigned int authsize_val;
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	unsigned int expected_ivlen;
	size_t total_kernel_buffer_needed;

	if (!tfm_ud->req) {
		return luaL_error(L, "aead_tfm:encrypt: TFM request not initialized (internal error)");
	}

	// IV setup (adapted from luacrypto_aead_request_set_iv)
	expected_ivlen = crypto_aead_ivsize(tfm_ud->tfm);
	luaL_argcheck(L, iv_s_len == expected_ivlen, 2, "incorrect IV length");
	kfree(tfm_ud->iv_data);
	tfm_ud->iv_data = kmemdup(iv_s, iv_s_len, gfp);
	if (!tfm_ud->iv_data) {
		tfm_ud->iv_len = 0;
		return luaL_error(L, "aead_tfm:encrypt: failed to allocate IV buffer");
	}
	tfm_ud->iv_len = iv_s_len;

	// Data setup (adapted from luacrypto_aead_request_set_data)
	luaL_argcheck(L, aad_l >= 0 && (size_t)aad_l <= combined_s_len, 4, "AAD length out of bounds");
	aad_s_len = (size_t)aad_l;
	actual_data_s_len = combined_s_len - aad_s_len; // Plaintext length

	authsize_val = crypto_aead_authsize(tfm_ud->tfm);
	total_kernel_buffer_needed = aad_s_len + actual_data_s_len + authsize_val;

	if (!tfm_ud->work_buffer || tfm_ud->work_buffer_len < total_kernel_buffer_needed) {
		kfree(tfm_ud->work_buffer);
		tfm_ud->work_buffer = kmalloc(total_kernel_buffer_needed, gfp);
		if (!tfm_ud->work_buffer) {
			tfm_ud->work_buffer_len = 0;
			return luaL_error(L, "aead_tfm:encrypt: failed to allocate work buffer");
		}
		tfm_ud->work_buffer_len = total_kernel_buffer_needed;
	}

	memcpy(tfm_ud->work_buffer, combined_s, combined_s_len); // Copies AAD || Plaintext

	tfm_ud->aad_len_in_buffer = aad_s_len;
	tfm_ud->crypt_data_len_in_buffer = actual_data_s_len; // Plaintext length

	// Scatterlist covers AAD, plaintext, and space for tag.
	sg_init_one(&tfm_ud->sg_work, tfm_ud->work_buffer, aad_s_len + actual_data_s_len + authsize_val);

	aead_request_set_ad(tfm_ud->req, aad_s_len);
	aead_request_set_crypt(tfm_ud->req, &tfm_ud->sg_work, &tfm_ud->sg_work, actual_data_s_len, tfm_ud->iv_data);
	aead_request_set_callback(tfm_ud->req, 0, NULL, NULL);

	ret = crypto_aead_encrypt(tfm_ud->req);
	if (ret) {
		return luaL_error(L, "aead_tfm:encrypt: encryption failed (err %d)", ret);
	}

	// After encryption, work_buffer contains: AAD || Ciphertext || Tag.
	// Lua wrapper expects this full AAD || Ciphertext || Tag output.
	lua_pushlstring(
		L, (const char *)(tfm_ud->work_buffer),
		tfm_ud->aad_len_in_buffer + tfm_ud->crypt_data_len_in_buffer + authsize_val
	);
	return 1;
}

static int luacrypto_aead_tfm_decrypt(lua_State *L) {
	luacrypto_aead_tfm_t *tfm_ud = luacrypto_check_aead_tfm(L, 1);
	size_t iv_s_len, combined_s_len, aad_s_len, actual_data_s_len;
	const char *iv_s = luaL_checklstring(L, 2, &iv_s_len);
	// combined_s is AAD || CiphertextWithTag
	const char *combined_s = luaL_checklstring(L, 3, &combined_s_len);
	lua_Integer aad_l = luaL_checkinteger(L, 4);
	int ret;
	unsigned int authsize_val;
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	unsigned int expected_ivlen;
	size_t total_kernel_buffer_needed;

	if (!tfm_ud->req) {
		return luaL_error(L, "aead_tfm:decrypt: TFM request not initialized (internal error)");
	}

	// IV setup
	expected_ivlen = crypto_aead_ivsize(tfm_ud->tfm);
	luaL_argcheck(L, iv_s_len == expected_ivlen, 2, "incorrect IV length");
	kfree(tfm_ud->iv_data);
	tfm_ud->iv_data = kmemdup(iv_s, iv_s_len, gfp);
	if (!tfm_ud->iv_data) {
		tfm_ud->iv_len = 0;
		return luaL_error(L, "aead_tfm:decrypt: failed to allocate IV buffer");
	}
	tfm_ud->iv_len = iv_s_len;

	// Data setup
	luaL_argcheck(L, aad_l >= 0 && (size_t)aad_l <= combined_s_len, 4, "AAD length out of bounds");
	aad_s_len = (size_t)aad_l;
	actual_data_s_len = combined_s_len - aad_s_len; // CiphertextWithTag length

	authsize_val = crypto_aead_authsize(tfm_ud->tfm);
	// For decryption, work_buffer needs to hold AAD || CiphertextWithTag initially.
	// The output (AAD || Plaintext) will be shorter or same length.
	// Kernel expects source buffer to be large enough for AAD + CT + Tag.
	// Destination (which is same buffer) will receive AAD + PT.
	// So, initial combined_s_len is AAD + CT + Tag.
	total_kernel_buffer_needed = combined_s_len; // aad_s_len + actual_data_s_len

	if (!tfm_ud->work_buffer || tfm_ud->work_buffer_len < total_kernel_buffer_needed) {
		kfree(tfm_ud->work_buffer);
		tfm_ud->work_buffer = kmalloc(total_kernel_buffer_needed, gfp);
		if (!tfm_ud->work_buffer) {
			tfm_ud->work_buffer_len = 0;
			return luaL_error(L, "aead_tfm:decrypt: failed to allocate work buffer");
		}
		tfm_ud->work_buffer_len = total_kernel_buffer_needed;
	}

	memcpy(tfm_ud->work_buffer, combined_s, combined_s_len); // Copies AAD || CiphertextWithTag

	tfm_ud->aad_len_in_buffer = aad_s_len;
	tfm_ud->crypt_data_len_in_buffer = actual_data_s_len; // CiphertextWithTag length

	// Scatterlist covers AAD and CiphertextWithTag.
	sg_init_one(&tfm_ud->sg_work, tfm_ud->work_buffer, aad_s_len + actual_data_s_len);

	aead_request_set_ad(tfm_ud->req, aad_s_len);
	aead_request_set_crypt(tfm_ud->req, &tfm_ud->sg_work, &tfm_ud->sg_work, actual_data_s_len, tfm_ud->iv_data);
	aead_request_set_callback(tfm_ud->req, 0, NULL, NULL);

	ret = crypto_aead_decrypt(tfm_ud->req);
	if (ret) {
		// Common error is -EBADMSG for authentication failure
		return luaL_error(L, "aead_tfm:decrypt: decryption failed (err %d, possibly auth error)", ret);
	}

	// After decryption, work_buffer contains: AAD || Plaintext.
	// The length of Plaintext is (ciphertext_with_tag_len - authsize_val)
	luaL_argcheck(
		L, tfm_ud->crypt_data_len_in_buffer >= authsize_val,
		3, "input data (ciphertext+tag) too short for tag"
	);
	// The length of this combined data is (aad_len_in_buffer + plaintext_len)
	lua_pushlstring(
		L, (const char *)(tfm_ud->work_buffer),
		tfm_ud->aad_len_in_buffer + (tfm_ud->crypt_data_len_in_buffer - authsize_val)
	);
	return 1;
}

static const luaL_Reg luacrypto_aead_tfm_mt[] = {
	{"setkey", luacrypto_aead_tfm_setkey},
	{"setauthsize", luacrypto_aead_tfm_setauthsize},
	{"ivsize", luacrypto_aead_tfm_ivsize},
	{"authsize", luacrypto_aead_tfm_authsize},
	{"encrypt", luacrypto_aead_tfm_encrypt},
	{"decrypt", luacrypto_aead_tfm_decrypt},
	{"__gc", lunatik_deleteobject},
	{"__close", lunatik_closeobject},
	{"__index", lunatik_monitorobject},
	{NULL, NULL}
};

static const lunatik_class_t luacrypto_aead_tfm_class = {
	.name = "crypto_aead_tfm",
	.methods = luacrypto_aead_tfm_mt,
	.release = luacrypto_aead_tfm_release,
	.sleep = true,
};

/* --- SHASH Transform (tfm) Userdata --- */
#define LUACRYPTO_SHASH_TFM_NAME "crypto_shash_tfm"

typedef struct {
	struct crypto_shash *tfm;
	struct shash_desc *kernel_desc; // Points to kmalloc'ed shash_desc + space
	size_t desc_alloc_len;       // Allocated size of kernel_desc
} luacrypto_shash_tfm_t;

LUNATIK_PRIVATECHECKER(luacrypto_check_shash_tfm, luacrypto_shash_tfm_t *);

static void luacrypto_shash_tfm_release(void *private)
{
	luacrypto_shash_tfm_t *tfm_ud = (luacrypto_shash_tfm_t *)private;
	if (!tfm_ud) {
		return;
	}
	kfree(tfm_ud->kernel_desc); // This was kmalloc'ed in shash_new
	tfm_ud->kernel_desc = NULL;
	if (tfm_ud->tfm && !IS_ERR(tfm_ud->tfm)) {
		crypto_free_shash(tfm_ud->tfm);
	}
}

/* --- SHASH TFM Methods --- */

static int luacrypto_shash_tfm_digestsize(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	lua_pushinteger(L, crypto_shash_digestsize(tfm_ud->tfm));
	return 1;
}

static int luacrypto_shash_tfm_setkey(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	size_t keylen;
	const char *key = luaL_checklstring(L, 2, &keylen);
	int ret = crypto_shash_setkey(tfm_ud->tfm, key, keylen);
	if (ret) return luaL_error(L, "shash_tfm:setkey: failed (%d)", ret);
	return 0;
}

// Methods moved from shash_desc to shash_tfm
static int luacrypto_shash_tfm_digest(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	size_t datalen;
	const char *data = luaL_checklstring(L, 2, &datalen);
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	unsigned int digestsize = crypto_shash_digestsize(tfm_ud->tfm);
	u8 *digest_buf = kmalloc(digestsize, gfp);
	if (!digest_buf) return luaL_error(L, "shash_tfm:digest: failed to allocate digest buffer");
	int ret = crypto_shash_digest(tfm_ud->kernel_desc, data, datalen, digest_buf);
	if (ret) {
		kfree(digest_buf);
		return luaL_error(L, "shash_tfm:digest: crypto_shash_digest failed (%d)", ret);
	}
	lua_pushlstring(
		L, (const char *)digest_buf, digestsize
	);
	kfree(digest_buf);
	return 1;
}

static int luacrypto_shash_tfm_init(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	int ret = crypto_shash_init(tfm_ud->kernel_desc);
	if (ret) {
		return luaL_error(L, "shash_tfm:init: failed (%d)", ret);
	}
	return 0;
}

static int luacrypto_shash_tfm_update(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	size_t datalen;
	const char *data = luaL_checklstring(L, 2, &datalen);
	int ret = crypto_shash_update(tfm_ud->kernel_desc, data, datalen);
	if (ret) {
		return luaL_error(L, "shash_tfm:update: failed (%d)", ret);
	}
	return 0;
}

static int luacrypto_shash_tfm_final(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	unsigned int digestsize = crypto_shash_digestsize(tfm_ud->tfm);
	u8 *digest_buf = kmalloc(digestsize, gfp);
	int ret;
	if (!digest_buf) return luaL_error(L, "shash_tfm:final: failed to allocate digest buffer");
	ret = crypto_shash_final(tfm_ud->kernel_desc, digest_buf);
	if (ret) {
		kfree(digest_buf);
		return luaL_error(L, "shash_tfm:final: failed (%d)", ret);
	}
	lua_pushlstring(
		L, (const char *)digest_buf, digestsize
	);
	kfree(digest_buf);
	return 1;
}

static int luacrypto_shash_tfm_finup(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	size_t datalen;
	const char *data = luaL_checklstring(L, 2, &datalen);
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	unsigned int digestsize = crypto_shash_digestsize(tfm_ud->tfm);
	u8 *digest_buf = kmalloc(digestsize, gfp);
	int ret;
	if (!digest_buf) return luaL_error(L, "shash_tfm:finup: failed to allocate digest buffer");
	ret = crypto_shash_finup(tfm_ud->kernel_desc, data, datalen, digest_buf);
	if (ret) {
		kfree(digest_buf);
		return luaL_error(L, "shash_tfm:finup: failed (%d)", ret);
	}
	lua_pushlstring(
		L, (const char *)digest_buf, digestsize
	);
	kfree(digest_buf);
	return 1;
}

static int luacrypto_shash_tfm_export(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	unsigned int statesize = crypto_shash_statesize(tfm_ud->tfm);
	void *state_buf = kmalloc(statesize, gfp);
	if (!state_buf) return luaL_error(L, "shash_tfm:export: failed to allocate state buffer");
	crypto_shash_export(tfm_ud->kernel_desc, state_buf);
	lua_pushlstring(
		L, (const char *)state_buf, statesize
	);
	kfree(state_buf);
	return 1;
}

static int luacrypto_shash_tfm_import(lua_State *L) {
	luacrypto_shash_tfm_t *tfm_ud = luacrypto_check_shash_tfm(L, 1);
	size_t statelen;
	const char *state = luaL_checklstring(L, 2, &statelen);
	unsigned int expected_statesize;
	int ret;
	expected_statesize = crypto_shash_statesize(tfm_ud->tfm);
	luaL_argcheck(
		L, statelen == expected_statesize,
		2, "incorrect state length for import"
	);
	ret = crypto_shash_import(tfm_ud->kernel_desc, state);
	if (ret) return luaL_error(L, "shash_tfm:import: failed (%d)", ret);
	return 0;
}

static const luaL_Reg luacrypto_shash_tfm_mt[] = {
	{"digestsize", luacrypto_shash_tfm_digestsize},
	{"setkey", luacrypto_shash_tfm_setkey},
	// Methods moved from shash_desc
	{"digest", luacrypto_shash_tfm_digest},
	{"init", luacrypto_shash_tfm_init},
	{"update", luacrypto_shash_tfm_update},
	{"final", luacrypto_shash_tfm_final},
	{"finup", luacrypto_shash_tfm_finup},
	{"export", luacrypto_shash_tfm_export},
	{"import", luacrypto_shash_tfm_import},
	// Standard metamethods
	{"__gc", lunatik_deleteobject},
	{"__close", lunatik_closeobject},
	{"__index", lunatik_monitorobject},
	{NULL, NULL}
};

static const lunatik_class_t luacrypto_shash_tfm_class = {
	.name = LUACRYPTO_SHASH_TFM_NAME,
	.methods = luacrypto_shash_tfm_mt,
	.release = luacrypto_shash_tfm_release,
	.sleep = true
};


/* --- Constructor for AEAD module ("crypto_aead") --- */
// This function will be exposed as crypto_aead.new() in Lua.
static int luacrypto_aead_new(lua_State *L) {
	const char *algname = luaL_checkstring(L, 1);
	luacrypto_aead_tfm_t *tfm_ud;
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	lunatik_object_t *object = lunatik_newobject(
		L, &luacrypto_aead_tfm_class,
		sizeof(luacrypto_aead_tfm_t)
	);
	if (!object) {
		return luaL_error(L, "crypto_aead.new: failed to create underlying AEAD TFM object");
	}
	tfm_ud = (luacrypto_aead_tfm_t *)object->private;
	memset(tfm_ud, 0, sizeof(luacrypto_aead_tfm_t));

	struct crypto_aead *tfm =  crypto_alloc_aead(algname, 0, 0);
	tfm_ud->tfm = tfm;
	if (IS_ERR(tfm_ud->tfm)) {
		long err = PTR_ERR(tfm_ud->tfm);
		return luaL_error(L, "failed to allocate AEAD transform for %s (err %ld)", algname, err);
	}

	// Allocate aead_request
	tfm_ud->req = aead_request_alloc(tfm_ud->tfm, gfp);
	if (!tfm_ud->req) {
		// tfm_ud->tfm is guaranteed not IS_ERR here.
		crypto_free_aead(tfm_ud->tfm);
		tfm_ud->tfm = NULL; // Prevent double free in release
		return luaL_error(L, "crypto_aead.new: failed to allocate kernel request for %s",
					algname);
	}
	sg_init_one(&tfm_ud->sg_work, NULL, 0);
	return 1;
}


/* --- Constructor for SHASH module ("crypto_shash") --- */
// This function will be exposed as crypto_shash.new() in Lua.
static int luacrypto_shash_new(lua_State *L) {
	const char *algname = luaL_checkstring(L, 1);
	luacrypto_shash_tfm_t *tfm_ud;
	gfp_t gfp = lunatik_gfp(lunatik_toruntime(L));
	size_t desc_size;
	lunatik_object_t *object = lunatik_newobject(
		L, &luacrypto_shash_tfm_class,
		sizeof(luacrypto_shash_tfm_t)
	);
	if (!object) {
		return luaL_error(L, "crypto_shash.new: failed to create underlying SHASH TFM object");
	}
	tfm_ud = (luacrypto_shash_tfm_t *)object->private;
	memset(tfm_ud, 0, sizeof(luacrypto_shash_tfm_t));

	tfm_ud->tfm = crypto_alloc_shash(algname, 0, 0);
	if (IS_ERR(tfm_ud->tfm)) {
		long err = PTR_ERR(tfm_ud->tfm);
		return luaL_error(L, "failed to allocate SHASH transform for %s (err %ld)", algname, err);
	}

	// Allocate shash_desc
	desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm_ud->tfm);
	tfm_ud->kernel_desc = kmalloc(desc_size, gfp);
	if (!tfm_ud->kernel_desc) {
		// tfm_ud->tfm is guaranteed not IS_ERR here.
		crypto_free_shash(tfm_ud->tfm);
		tfm_ud->tfm = NULL; // Prevent double free in release
		return luaL_error(L, "crypto_shash.new: failed to allocate descriptor memory for %s",
					algname);
	}
	tfm_ud->kernel_desc->tfm = tfm_ud->tfm;
	tfm_ud->desc_alloc_len = desc_size;
	return 1;
}


static const luaL_Reg luacrypto_aead_lib_funcs[] = {
	{"new", luacrypto_aead_new},
	{NULL, NULL}
};

static const luaL_Reg luacrypto_shash_lib_funcs[] = {
	{"new", luacrypto_shash_new},
	{NULL, NULL}
};

LUNATIK_NEWLIB(crypto_aead, luacrypto_aead_lib_funcs, &luacrypto_aead_tfm_class, NULL);
LUNATIK_NEWLIB(crypto_shash, luacrypto_shash_lib_funcs, &luacrypto_shash_tfm_class, NULL);

static int __init luacrypto_init(void)
{
	return 0;
}

static void __exit luacrypto_exit(void)
{
}

module_init(luacrypto_init);
module_exit(luacrypto_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("jperon <cataclop@hotmail.com>");
MODULE_DESCRIPTION("Lunatik low-level Linux Crypto API interface");


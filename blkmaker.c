/*
 * Copyright 2012-2016 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <blkmaker.h>
#include <blktemplate.h>

#include "private.h"

const char *blkmk_supported_rules[] = {
	"csv",
	"segwit",
	NULL
};

bool blkmk_supports_rule(const char * const rulename) {
	for (const char **r = blkmk_supported_rules; *r; ++r) {
		if (!strcmp(rulename, *r)) {
			return true;
		}
	}
	return false;
}

static inline
void my_htole32(unsigned char *buf, uint32_t n) {
	buf[0] = (n >>  0) % 256;
	buf[1] = (n >>  8) % 256;
	buf[2] = (n >> 16) % 256;
	buf[3] = (n >> 24) % 256;
}

static inline
void my_htole64(unsigned char *buf, uint64_t n) {
	for (int i = 0; i < 8; ++i)
		buf[i] = (n >>  (8*i)) & 0xff;
}


bool (*blkmk_sha256_impl)(void *, const void *, size_t) = NULL;

bool _blkmk_dblsha256(void *hash, const void *data, size_t datasz) {
	return blkmk_sha256_impl(hash, data, datasz) && blkmk_sha256_impl(hash, hash, 32);
}

#define dblsha256 _blkmk_dblsha256

static
size_t varintDecode(const uint8_t *p, size_t size, uint64_t *n)
{
	if (size > 8 && p[0] == 0xff)
	{
		*n = upk_u64le(p, 1);
		return 9;
	}
	if (size > 4 && p[0] == 0xfe)
	{
		*n = upk_u32le(p, 1);
		return 5;
	}
	if (size > 2 && p[0] == 0xfd)
	{
		*n = upk_u16le(p, 1);
		return 3;
	}
	if (size > 0 && p[0] <= 0xfc)
	{
		*n = p[0];
		return 1;
	}
	return 0;
}

#define max_varint_size (9)

static
char varintEncode(unsigned char *out, uint64_t n) {
	if (n < 0xfd)
	{
		out[0] = n;
		return 1;
	}
	char L;
	if (n <= 0xffff)
	{
		out[0] = '\xfd';
		L = 3;
	}
	else
	if (n <= 0xffffffff)
	{
		out[0] = '\xfe';
		L = 5;
	}
	else
	{
		out[0] = '\xff';
		L = 9;
	}
	for (unsigned char i = 1; i < L; ++i)
		out[i] = (n >> ((i - 1) * 8)) % 256;
	return L;
}

static uint8_t blkmk_varint_encode_size(const uint64_t n) {
	uint8_t dummy[max_varint_size];
	return varintEncode(dummy, n);
}

static
int16_t blkmk_count_sigops(const uint8_t * const script, const size_t scriptsz, const bool bip141) {
	int16_t sigops = 0;
	for (size_t i = 0; i < scriptsz; ++i) {
		if (script[i] <= 0x4c /* OP_PUSHDATA1 */) {
			if (script[i] == 0x4c) {
				if (i + 1 >= scriptsz) {
					break;
				}
				++i;
			}
			i += script[i];
		} else if (script[i] == 0x4d /* OP_PUSHDATA2 */) {
			if (i + 2 >= scriptsz) {
				break;
			}
			i += 2 + upk_u16le(script, i + 1);
		} else if (script[i] == 0x4e /* OP_PUSHDATA4 */) {
			if (i + 4 >= scriptsz) {
				break;
			}
			i += 4 + upk_u32le(script, i + 1);
		} else if (script[i] == 0xac /* OP_CHECKSIG */ || script[i] == 0xad /* OP_CHECKSIGVERIFY */) {
			++sigops;
		} else if (script[i] == 0xae /* OP_CHECKMULTISIG */ || script[i] == 0xaf /* OP_CHECKMULTISIGVERIFY */) {
			sigops += 20;
		}
	}
	if (bip141) {
		sigops *= 4;
	}
	return sigops;
}

static int64_t blkmk_calc_gentx_weight(const void * const data, const size_t datasz) {
	return (datasz * 4) + 2 /* marker & flag */ + 1 /* witness stack count */ + 1 /* stack item size */ + 32 /* stack item: nonce */;
}

static int64_t blktxn_set_gentx_weight(struct blktxn_t * const gentx) {
	if (gentx->weight < 0) {
		gentx->weight = blkmk_calc_gentx_weight(gentx->data, gentx->datasz);
	}
	return gentx->weight;
}

uint64_t blkmk_init_generation3(blktemplate_t * const tmpl, const void * const script, const size_t scriptsz, bool * const inout_newcb) {
	if (tmpl->cbtxn && !(*inout_newcb && (tmpl->mutations & BMM_GENERATE)))
	{
		*inout_newcb = false;
		return 0;
	}
	
	if (!tmpl->cbvalue) {
		// TODO: Figure it out from the existing cbtxn
		*inout_newcb = false;
		return 0;
	}
	
	*inout_newcb = true;
	
	if (scriptsz >= 0xfd)
		return 0;
	
	unsigned char *data = malloc(168 + scriptsz);
	size_t off = 0;
	if (!data)
		return 0;
	
	memcpy(&data[0],
		"\x01\0\0\0"  // txn ver
		"\x01"        // input count
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"  // prevout
			"\xff\xff\xff\xff"  // index (-1)
			"\x02"              // scriptSig length
			// height serialization length (set later)
		, 42);
	off += 43;
	
	blkheight_t h = tmpl->height;
	while (h > 127)
	{
		++data[41];
		data[off++] = h & 0xff;
		h >>= 8;
	}
	data[off++] = h;
	data[42] = data[41] - 1;
	
	if (tmpl->aux_count)
	{
		unsigned auxsz = off++;
		data[auxsz] = 0;
		++data[41];
		
		for (unsigned i = 0; i < tmpl->aux_count; ++i)
		{
			struct blkaux_t * const aux = &tmpl->auxs[i];
			if ((size_t)data[41] + aux->datasz > libblkmaker_coinbase_size_limit)
			{
				free(data);
				return 0;
			}
			memcpy(&data[off], tmpl->auxs[i].data, aux->datasz);
			data[41] += aux->datasz;
			data[auxsz] += aux->datasz;
			off += aux->datasz;
		}
	}
	
	memcpy(&data[off],
			"\xff\xff\xff\xff"  // sequence
		"\x01"        // output count
		, 5);
	off += 5;
	my_htole64(&data[off], tmpl->cbvalue);
	off += 8;
	data[off++] = scriptsz;
	if (scriptsz) {
		memcpy(&data[off], script, scriptsz);
		off += scriptsz;
	}
	memset(&data[off], 0, 4);  // lock time
	off += 4;
	
	const unsigned long pretx_size = libblkmaker_blkheader_size + blkmk_varint_encode_size(1 + tmpl->txncount);
	const int16_t sigops_counted = blkmk_count_sigops(script, scriptsz, tmpl->_bip141_sigops);
	const int64_t gentx_weight = blkmk_calc_gentx_weight(data, off);
	if (pretx_size + tmpl->txns_datasz + off > tmpl->sizelimit
	 || (tmpl->txns_weight >= 0 && tmpl->txns_weight + gentx_weight > tmpl->weightlimit)
	 || (tmpl->txns_sigops >= 0 && tmpl->txns_sigops + sigops_counted > tmpl->sigoplimit)) {
		free(data);
		return 0;
	}
	
	struct blktxn_t *txn = malloc(sizeof(*tmpl->cbtxn));
	if (!txn)
	{
		free(data);
		return 0;
	}
	blktxn_init(txn);
	
	txn->data = data;
	txn->datasz = off;
	txn->sigops_ = sigops_counted;
	txn->weight = gentx_weight;
	
	if (tmpl->cbtxn)
	{
		blktxn_clean(tmpl->cbtxn);
		free(tmpl->cbtxn);
	}
	tmpl->cbtxn = txn;
	
	tmpl->mutations |= BMM_CBAPPEND | BMM_CBSET | BMM_GENERATE;
	
	return tmpl->cbvalue;
}

uint64_t blkmk_init_generation2(blktemplate_t *tmpl, void *script, size_t scriptsz, bool *out_newcb) {
	bool tmp;
	if (!out_newcb)
		out_newcb = &tmp;
	*out_newcb = false;
	return blkmk_init_generation3(tmpl, script, scriptsz, out_newcb);
}

uint64_t blkmk_init_generation(blktemplate_t *tmpl, void *script, size_t scriptsz) {
	return blkmk_init_generation2(tmpl, script, scriptsz, NULL);
}

static
bool blkmk_hash_transactions(blktemplate_t * const tmpl)
{
	for (unsigned long i = 0; i < tmpl->txncount; ++i)
	{
		struct blktxn_t * const txn = &tmpl->txns[i];
		if (txn->hash_)
			continue;
		txn->hash_ = malloc(sizeof(*txn->hash_));
		if (!dblsha256(txn->hash_, txn->data, txn->datasz))
		{
			free(txn->hash_);
			return false;
		}
	}
	return true;
}

static
bool blkmk_build_merkle_branches(blktemplate_t * const tmpl)
{
	int branchcount, i;
	libblkmaker_hash_t *branches;
	
	if (tmpl->_mrklbranch)
		return true;
	
	if (!blkmk_hash_transactions(tmpl))
		return false;
	
	branchcount = blkmk_flsl(tmpl->txncount);
	if (!branchcount)
	{
		tmpl->_mrklbranchcount = 0;
		tmpl->_mrklbranch = NULL;
		return true;
	}
	
	branches = malloc(branchcount * sizeof(*branches));
	if (!branches) {
		return false;
	}
	
	size_t hashcount = tmpl->txncount + 1;
	libblkmaker_hash_t * const hashes = malloc((hashcount + 1) * sizeof(*hashes));  // +1 for when the last needs duplicating
	if (!hashes) {
		free(branches);
		return false;
	}
	
	for (i = 0; i < tmpl->txncount; ++i)
	{
		struct blktxn_t * const txn = &tmpl->txns[i];
		txnhash_t * const txid = txn->txid ? txn->txid : txn->hash_;
		memcpy(&hashes[i + 1], txid, sizeof(*hashes));
	}
	
	for (i = 0; i < branchcount; ++i)
	{
		memcpy(&branches[i], &hashes[1], sizeof(*hashes));
		if (hashcount % 2)
		{
			memcpy(&hashes[hashcount], &hashes[hashcount - 1], sizeof(*hashes));
			++hashcount;
		}
		for (size_t i = 2; i < hashcount; i += 2)
			// This is where we overlap input and output, on the first pair
			if (!dblsha256(&hashes[i / 2], &hashes[i], sizeof(*hashes) * 2))
			{
				free(branches);
				free(hashes);
				return false;
			}
		hashcount /= 2;
	}
	
	free(hashes);
	
	tmpl->_mrklbranch = branches;
	tmpl->_mrklbranchcount = branchcount;
	
	return true;
}

static
bool build_merkle_root(unsigned char *mrklroot_out, blktemplate_t *tmpl, unsigned char *cbtxndata, size_t cbtxndatasz) {
	int i;
	libblkmaker_hash_t hashes[0x40];
	
	if (!blkmk_build_merkle_branches(tmpl))
		return false;
	
	if (!dblsha256(&hashes[0], cbtxndata, cbtxndatasz))
		return false;
	
	for (i = 0; i < tmpl->_mrklbranchcount; ++i)
	{
		memcpy(&hashes[1], tmpl->_mrklbranch[i], 0x20);
		// This is where we overlap input and output, on the first pair
		if (!dblsha256(&hashes[0], &hashes[0], 0x40))
			return false;
	}
	
	memcpy(mrklroot_out, &hashes[0], 32);
	
	return true;
}

static
bool _blkmk_calculate_witness_mrklroot(blktemplate_t * const tmpl, libblkmaker_hash_t * const out, bool * const witness_needed) {
	if (!blkmk_hash_transactions(tmpl))
		return false;
	
	// Step 1: Populate hashes with the witness hashes for all transactions
	size_t hashcount = tmpl->txncount + 1;
	libblkmaker_hash_t * const hashes = malloc((hashcount + 1) * sizeof(*hashes));  // +1 for when the last needs duplicating
	if (!hashes) {
		return false;
	}
	memset(&hashes[0], 0, sizeof(hashes[0]));  // Gen tx gets a null entry
	*witness_needed = false;
	for (unsigned long i = 0; i < tmpl->txncount; ++i) {
		struct blktxn_t * const txn = &tmpl->txns[i];
		if (txn->txid && memcmp(txn->hash_, txn->txid, sizeof(*txn->txid))) {
			*witness_needed = true;
		}
		memcpy(&hashes[i + 1], txn->hash_, sizeof(*hashes));
	}
	if (!*witness_needed) {
		free(hashes);
		return true;
	}
	
	// Step 2: Reduce it to a merkle root
	for ( ; hashcount > 1 ; hashcount /= 2) {
		if (hashcount % 2 == 1) {
			// Odd number, duplicate the last
			memcpy(&hashes[hashcount], &hashes[hashcount - 1], sizeof(*hashes));
			++hashcount;
		}
		for (size_t i = 0; i < hashcount; i += 2) {
			// We overlap input and output here, on the first pair
			if (!dblsha256(&hashes[i / 2], &hashes[i], sizeof(*hashes) * 2)) {
				free(hashes);
				return false;
			}
		}
	}
	
	memcpy(out, hashes, sizeof(*out));
	free(hashes);
	return true;
}

static
bool _blkmk_witness_mrklroot(blktemplate_t * const tmpl) {
	if (tmpl->_calculated_witness) {
		// Already calculated
		return true;
	}
	tmpl->_witnessmrklroot = malloc(sizeof(libblkmaker_hash_t));
	if (!tmpl->_witnessmrklroot) {
		return false;
	}
	bool witness_needed;
	if (!_blkmk_calculate_witness_mrklroot(tmpl, tmpl->_witnessmrklroot, &witness_needed)) {
		free(tmpl->_witnessmrklroot);
		tmpl->_witnessmrklroot = NULL;
		return false;
	}
	if (!witness_needed) {
		free(tmpl->_witnessmrklroot);
		tmpl->_witnessmrklroot = NULL;
	}
	tmpl->_calculated_witness = true;
	return true;
}

static const int cbScriptSigLen = 4 + 1 + 36;

static
bool _blkmk_append_cb(blktemplate_t * const tmpl, void * const vout, const void * const append, const size_t appendsz, size_t * const appended_at_offset, int16_t * const sigops_counted_p) {
	unsigned char *out = vout;
	unsigned char *in = tmpl->cbtxn->data;
	size_t insz = tmpl->cbtxn->datasz;
	
	if (appendsz > libblkmaker_coinbase_size_limit || in[cbScriptSigLen] > libblkmaker_coinbase_size_limit - appendsz) {
		return false;
	}
	
	const unsigned long pretx_size = libblkmaker_blkheader_size + blkmk_varint_encode_size(1 + tmpl->txncount);
	if (pretx_size + tmpl->cbtxn->datasz + tmpl->txns_datasz + appendsz > tmpl->sizelimit) {
		return false;
	}
	
	if (tmpl->txns_weight >= 0 && (blktxn_set_gentx_weight(tmpl->cbtxn) + tmpl->txns_weight + (appendsz * 4) > tmpl->weightlimit)) {
		return false;
	}
	
	const int16_t orig_scriptSig_sigops = blkmk_count_sigops(&in[cbScriptSigLen + 1], in[cbScriptSigLen], tmpl->_bip141_sigops);
	int cbPostScriptSig = cbScriptSigLen + 1 + in[cbScriptSigLen];
	if (appended_at_offset)
		*appended_at_offset = cbPostScriptSig;
	unsigned char *outPostScriptSig = &out[cbPostScriptSig];
	void *outExtranonce = (void*)outPostScriptSig;
	outPostScriptSig += appendsz;
	
	if (out != in)
	{
		memcpy(out, in, cbPostScriptSig+1);
		memcpy(outPostScriptSig, &in[cbPostScriptSig], insz - cbPostScriptSig);
	}
	else
		memmove(outPostScriptSig, &in[cbPostScriptSig], insz - cbPostScriptSig);
	
	out[cbScriptSigLen] += appendsz;
	memcpy(outExtranonce, append, appendsz);
	
	const int16_t sigops_counted = tmpl->cbtxn->sigops_ + blkmk_count_sigops(&out[cbScriptSigLen + 1], out[cbScriptSigLen], tmpl->_bip141_sigops) - orig_scriptSig_sigops;
	if (tmpl->txns_sigops >= 0 && tmpl->txns_sigops + sigops_counted > tmpl->sigoplimit) {
		// Overflowed :(
		if (out == in) {
			// Revert it!
			out[cbScriptSigLen] -= appendsz;
			memmove(&out[cbPostScriptSig], outPostScriptSig, insz - cbPostScriptSig);
		}
		return false;
	}
	
	if (sigops_counted_p) {
		*sigops_counted_p = sigops_counted;
	}
	
	return true;
}

ssize_t blkmk_append_coinbase_safe2(blktemplate_t * const tmpl, const void * const append, const size_t appendsz, int extranoncesz, const bool merkle_only)
{
	if (!(tmpl->mutations & (BMM_CBAPPEND | BMM_CBSET)))
		return -1;
	
	size_t datasz = tmpl->cbtxn->datasz;
	if (extranoncesz == sizeof(unsigned int)) {
		++extranoncesz;
	} else
	if (!merkle_only)
	{
		if (extranoncesz < sizeof(unsigned int))
			extranoncesz = sizeof(unsigned int);
	}
	if (tmpl->cbtxn->datasz <= cbScriptSigLen || tmpl->cbtxn->datasz <= cbScriptSigLen + tmpl->cbtxn->data[cbScriptSigLen]) {
		return -6;
	}
	if (extranoncesz > libblkmaker_coinbase_size_limit || tmpl->cbtxn->data[cbScriptSigLen] > libblkmaker_coinbase_size_limit || extranoncesz + tmpl->cbtxn->data[cbScriptSigLen] > libblkmaker_coinbase_size_limit) {
		return -5;
	}
	size_t availsz = libblkmaker_coinbase_size_limit - extranoncesz - tmpl->cbtxn->data[cbScriptSigLen];
	{
		const unsigned long pretx_size = libblkmaker_blkheader_size + blkmk_varint_encode_size(1 + tmpl->txncount);
		const size_t current_blocksize = pretx_size + tmpl->cbtxn->datasz + tmpl->txns_datasz;
		if (current_blocksize > tmpl->sizelimit) {
			return -4;
		}
		const size_t availsz2 = tmpl->sizelimit - current_blocksize;
		if (availsz2 < availsz) {
			availsz = availsz2;
		}
	}
	if (tmpl->txns_weight >= 0) {
		const size_t current_blockweight = blktxn_set_gentx_weight(tmpl->cbtxn) + tmpl->txns_weight;
		if (current_blockweight > tmpl->weightlimit) {
			return false;
		}
		const size_t availsz2 = (tmpl->weightlimit - current_blockweight) / 4;
		if (availsz2 < availsz) {
			availsz = availsz2;
		}
	}
	if (appendsz > availsz)
		return availsz;
	
	void *newp = realloc(tmpl->cbtxn->data, datasz + appendsz);
	if (!newp)
		return -2;
	
	tmpl->cbtxn->data = newp;
	if (!_blkmk_append_cb(tmpl, newp, append, appendsz, NULL, &tmpl->cbtxn->sigops_))
		return -3;
	tmpl->cbtxn->datasz += appendsz;
	tmpl->cbtxn->weight += appendsz * 4;
	
	return availsz;
}

ssize_t blkmk_append_coinbase_safe(blktemplate_t * const tmpl, const void * const append, const size_t appendsz) {
	return blkmk_append_coinbase_safe2(tmpl, append, appendsz, 0, false);
}

bool _blkmk_extranonce(blktemplate_t *tmpl, void *vout, unsigned int workid, size_t *offs) {
	unsigned char *in = tmpl->cbtxn->data;
	size_t insz = tmpl->cbtxn->datasz;
	
	if (!workid)
	{
		memcpy(vout, in, insz);
		*offs += insz;
		return true;
	}
	
	if (!_blkmk_append_cb(tmpl, vout, &workid, sizeof(workid), NULL, NULL))
		return false;
	
	*offs += insz + sizeof(workid);
	
	return true;
}

static const unsigned char witness_magic[] = { 0x6a /* OP_RETURN */, 0x24, 0xaa, 0x21, 0xa9, 0xed };
#define commitment_spk_size (sizeof(witness_magic) + sizeof(libblkmaker_hash_t) /* witness mrklroot */)
#define commitment_txout_size (8 /* value */ + 1 /* scriptPubKey length */ + commitment_spk_size)
static const size_t max_witness_commitment_insert = max_varint_size + commitment_txout_size - 1;
static const libblkmaker_hash_t witness_nonce = { 0 };

static
bool _blkmk_insert_witness_commitment(blktemplate_t * const tmpl, unsigned char * const gentxdata, size_t * const gentxsize) {
	if (!_blkmk_witness_mrklroot(tmpl)) {
		return false;
	}
	if (!tmpl->_witnessmrklroot) {
		// No commitment needed
		return true;
	}

	libblkmaker_hash_t merkle_with_nonce[2];
	libblkmaker_hash_t commitment;
	memcpy(&merkle_with_nonce[0], tmpl->_witnessmrklroot, sizeof(*tmpl->_witnessmrklroot));
	memcpy(&merkle_with_nonce[1], &witness_nonce, sizeof(witness_nonce));
	if(!dblsha256(&commitment, &merkle_with_nonce[0], sizeof(merkle_with_nonce)))
		return false;
	
	if (cbScriptSigLen >= *gentxsize) {
		return false;
	}
	const uint8_t coinbasesz = gentxdata[cbScriptSigLen];
	const size_t offset_of_txout_count = cbScriptSigLen + coinbasesz + sizeof(coinbasesz) + 4 /* nSequence */;
	if (offset_of_txout_count >= *gentxsize) {
		return false;
	}
	uint64_t txout_count;
	const size_t in_txout_count_size = varintDecode(&gentxdata[offset_of_txout_count], *gentxsize - offset_of_txout_count, &txout_count);
	if (!in_txout_count_size) {
		return false;
	}
	++txout_count;
	unsigned char insertbuf[max_varint_size + commitment_txout_size];
	const size_t out_txout_count_size = varintEncode(insertbuf, txout_count);
	unsigned char * const commitment_txout = &insertbuf[out_txout_count_size];
	memset(commitment_txout, 0, 8);  // value
	commitment_txout[8] = commitment_spk_size;
	memcpy(&commitment_txout[9], witness_magic, sizeof(witness_magic));
	memcpy(&commitment_txout[9 + sizeof(witness_magic)], &commitment, sizeof(commitment));
	
	const size_t offset_of_txout_data = (offset_of_txout_count + in_txout_count_size);
	const size_t new_offset_of_preexisting_txout_data = (offset_of_txout_count + out_txout_count_size);
	const size_t length_of_txtail = 4;
	const size_t length_of_preexisting_txout_data = (*gentxsize - length_of_txtail) - offset_of_txout_data;
	const size_t offset_of_txtail_i = *gentxsize - length_of_txtail;  // just the lock time
	const size_t offset_of_txtail_o = offset_of_txtail_i + (out_txout_count_size - in_txout_count_size) + commitment_txout_size;
	memmove(&gentxdata[offset_of_txtail_o], &gentxdata[offset_of_txtail_i], length_of_txtail);
	if (offset_of_txout_data != new_offset_of_preexisting_txout_data) {
		memmove(&gentxdata[new_offset_of_preexisting_txout_data], &gentxdata[offset_of_txout_data], length_of_preexisting_txout_data);
	}
	memcpy(&gentxdata[offset_of_txout_count], insertbuf, out_txout_count_size);
	const size_t offset_of_commitment_txout_o = new_offset_of_preexisting_txout_data + length_of_preexisting_txout_data;
	memcpy(&gentxdata[offset_of_commitment_txout_o], commitment_txout, commitment_txout_size);
	
	*gentxsize = offset_of_txtail_o + length_of_txtail;
	
	return true;
}

static
void blkmk_set_times(blktemplate_t *tmpl, void * const out_hdrbuf, const time_t usetime, int16_t * const out_expire, const bool can_roll_ntime)
{
	double time_passed = difftime(usetime, tmpl->_time_rcvd);
	blktime_t timehdr = tmpl->curtime + time_passed;
	if (timehdr > tmpl->maxtime)
		timehdr = tmpl->maxtime;
	my_htole32(out_hdrbuf, timehdr);
	if (out_expire)
	{
		*out_expire = tmpl->expires - time_passed - 1;
		
		if (can_roll_ntime)
		{
			// If the caller can roll the time header, we need to expire before reaching the maxtime
			int16_t maxtime_expire_limit = (tmpl->maxtime - timehdr) + 1;
			if (*out_expire > maxtime_expire_limit)
				*out_expire = maxtime_expire_limit;
		}
	}
}

bool blkmk_sample_data_(blktemplate_t * const tmpl, uint8_t * const cbuf, const unsigned int dataid) {
	my_htole32(&cbuf[0], tmpl->version);
	memcpy(&cbuf[4], &tmpl->prevblk, 32);
	
	unsigned char cbtxndata[tmpl->cbtxn->datasz + sizeof(dataid) + max_witness_commitment_insert];
	size_t cbtxndatasz = 0;
	if (!_blkmk_extranonce(tmpl, cbtxndata, dataid, &cbtxndatasz))
		return false;
	if (!_blkmk_insert_witness_commitment(tmpl, cbtxndata, &cbtxndatasz)) {
		return false;
	}
	if (!build_merkle_root(&cbuf[36], tmpl, cbtxndata, cbtxndatasz))
		return false;
	
	my_htole32(&cbuf[0x44], tmpl->curtime);
	memcpy(&cbuf[72], &tmpl->diffbits, 4);
	
	return true;
}

size_t blkmk_get_data(blktemplate_t *tmpl, void *buf, size_t bufsz, time_t usetime, int16_t *out_expire, unsigned int *out_dataid) {
	if (!(blkmk_time_left(tmpl, usetime) && blkmk_work_left(tmpl) && tmpl->cbtxn))
		return 0;
	if (bufsz < 76)
		return 76;
	
	if (tmpl->cbtxn->datasz > cbScriptSigLen && tmpl->cbtxn->data[cbScriptSigLen] + sizeof(*out_dataid) < libblkmaker_coinbase_size_minimum) {
		// Add some padding
		const size_t padding_required = libblkmaker_coinbase_size_minimum - (tmpl->cbtxn->data[cbScriptSigLen] + sizeof(*out_dataid));
		uint8_t padding[padding_required];
		static const uint8_t opcode_nop = '\x61';
		memset(padding, opcode_nop, padding_required);
		if (padding_required != blkmk_append_coinbase_safe2(tmpl, padding, padding_required, 0, false)) {
			return 0;
		}
	}
	
	unsigned char *cbuf = buf;
	
	*out_dataid = tmpl->next_dataid++;
	if (!blkmk_sample_data_(tmpl, cbuf, *out_dataid))
		return 0;
	blkmk_set_times(tmpl, &cbuf[68], usetime, out_expire, false);
	
	return 76;
}

bool blkmk_get_mdata(blktemplate_t * const tmpl, void * const buf, const size_t bufsz, const time_t usetime, int16_t * const out_expire, void * const _out_cbtxn, size_t * const out_cbtxnsz, size_t * const cbextranonceoffset, int * const out_branchcount, void * const _out_branches, size_t extranoncesz, const bool can_roll_ntime)
{
	if (!(true
		&& blkmk_time_left(tmpl, usetime)
		&& tmpl->cbtxn
		&& blkmk_build_merkle_branches(tmpl)
		&& bufsz >= 76
		&& (tmpl->mutations & (BMM_CBAPPEND | BMM_CBSET))
	))
		return false;
	
	if (extranoncesz == sizeof(unsigned int))
		// Avoid overlapping with blkmk_get_data use
		++extranoncesz;
	
	if (tmpl->cbtxn->datasz > cbScriptSigLen && tmpl->cbtxn->data[cbScriptSigLen] + extranoncesz < libblkmaker_coinbase_size_minimum) {
		extranoncesz = libblkmaker_coinbase_size_minimum - tmpl->cbtxn->data[cbScriptSigLen];
	}
	
	void ** const out_branches = _out_branches;
	void ** const out_cbtxn = _out_cbtxn;
	unsigned char *cbuf = buf;
	
	my_htole32(&cbuf[0], tmpl->version);
	memcpy(&cbuf[4], &tmpl->prevblk, 32);
	
	*out_cbtxnsz = tmpl->cbtxn->datasz + extranoncesz;
	*out_cbtxn = malloc(*out_cbtxnsz + max_witness_commitment_insert);
	if (!*out_cbtxn)
		return false;
	unsigned char dummy[extranoncesz];
	memset(dummy, 0, extranoncesz);
	if (!_blkmk_append_cb(tmpl, *out_cbtxn, dummy, extranoncesz, cbextranonceoffset, NULL))
	{
		free(*out_cbtxn);
		return false;
	}
	if (!_blkmk_insert_witness_commitment(tmpl, *out_cbtxn, out_cbtxnsz)) {
		free(*out_cbtxn);
		return false;
	}
	
	blkmk_set_times(tmpl, &cbuf[68], usetime, out_expire, can_roll_ntime);
	memcpy(&cbuf[72], &tmpl->diffbits, 4);
	
	*out_branchcount = tmpl->_mrklbranchcount;
	const size_t branches_bytesz = (sizeof(libblkmaker_hash_t) * tmpl->_mrklbranchcount);
	*out_branches = malloc(branches_bytesz);
	if (!*out_branches)
	{
		free(*out_cbtxn);
		return false;
	}
	memcpy(*out_branches, tmpl->_mrklbranch, branches_bytesz);
	
	return true;
}

blktime_diff_t blkmk_time_left(const blktemplate_t *tmpl, time_t nowtime) {
	double age = difftime(nowtime, tmpl->_time_rcvd);
	if (age >= tmpl->expires)
		return 0;
	return tmpl->expires - age;
}

unsigned long blkmk_work_left(const blktemplate_t *tmpl) {
	if (!tmpl->version)
		return 0;
	if (!(tmpl->mutations & (BMM_CBAPPEND | BMM_CBSET)))
		return (tmpl->next_dataid) ? 0 : 1;
	return UINT_MAX - tmpl->next_dataid;
}

static char *blkmk_assemble_submission2_internal(blktemplate_t * const tmpl, const unsigned char * const data, const void * const extranonce, const size_t extranoncesz, blknonce_t nonce, const bool foreign)
{
	const bool incl_gentxn = (foreign || (!(tmpl->mutations & BMAb_TRUNCATE && !extranoncesz)));
	const bool incl_alltxn = (foreign || !(tmpl->mutations & BMAb_COINBASE));
	
	size_t blkbuf_sz = libblkmaker_blkheader_size;
	if (incl_gentxn) {
		blkbuf_sz += max_varint_size /* tx count */;
		blkbuf_sz += tmpl->cbtxn->datasz + extranoncesz + (max_varint_size - 1) /* possible enlargement to txout count when adding commitment output */ + commitment_txout_size;
		if (incl_alltxn) {
			blkbuf_sz += tmpl->txns_datasz;
		}
	}
	
	unsigned char * const blk = malloc(blkbuf_sz);
	if (!blk) {
		return NULL;
	}
	
	const size_t header_before_nonce_sz = libblkmaker_blkheader_size - sizeof(nonce);
	memcpy(blk, data, header_before_nonce_sz);
	nonce = htonl(nonce);
	memcpy(&blk[header_before_nonce_sz], &nonce, sizeof(nonce));
	size_t offs = libblkmaker_blkheader_size;
	
	if (incl_gentxn) {
		offs += varintEncode(&blk[offs], 1 + tmpl->txncount);
		
		size_t cbtxnlen = 0;
		// Essentially _blkmk_extranonce
		if (extranoncesz) {
			if (!_blkmk_append_cb(tmpl, &blk[offs], extranonce, extranoncesz, NULL, NULL)) {
				free(blk);
				return NULL;
			}
			
			cbtxnlen += tmpl->cbtxn->datasz + extranoncesz;
		} else {
			memcpy(&blk[offs], tmpl->cbtxn->data, tmpl->cbtxn->datasz);
			cbtxnlen += tmpl->cbtxn->datasz;
		}
		if (!_blkmk_insert_witness_commitment(tmpl, &blk[offs], &cbtxnlen)) {
			return NULL;
		}
		offs += cbtxnlen;
		
		if (incl_alltxn) {
			for (unsigned long i = 0; i < tmpl->txncount; ++i)
			{
				memcpy(&blk[offs], tmpl->txns[i].data, tmpl->txns[i].datasz);
				offs += tmpl->txns[i].datasz;
			}
		}
	}
	
	char *blkhex = malloc((offs * 2) + 1);
	_blkmk_bin2hex(blkhex, blk, offs);
	free(blk);
	
	return blkhex;
}

char *blkmk_assemble_submission2_(blktemplate_t * const tmpl, const unsigned char * const data, const void *extranonce, size_t extranoncesz, const unsigned int dataid, const blknonce_t nonce, const bool foreign)
{
	if (dataid) {
		if (extranoncesz) {
			// Cannot specify both!
			return NULL;
		}
		extranonce = &dataid;
		extranoncesz = sizeof(dataid);
	} else if (extranoncesz == sizeof(unsigned int)) {
		// Avoid overlapping with blkmk_get_data use
		unsigned char extended_extranonce[extranoncesz + 1];
		memcpy(extended_extranonce, extranonce, extranoncesz);
		extended_extranonce[extranoncesz] = 0;
		return blkmk_assemble_submission2_internal(tmpl, data, extended_extranonce, extranoncesz + 1, nonce, foreign);
	}
	return blkmk_assemble_submission2_internal(tmpl, data, extranonce, extranoncesz, nonce, foreign);
}

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <blkmaker.h>
#include <blktemplate.h>

#include "private.h"

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

uint64_t blkmk_init_generation(blktemplate_t *tmpl, void *script, size_t scriptsz) {
	if (tmpl->cbtxn)
		return 0;
	
	// Skip "no extranonce" scriptSig, since it would be too short (min 2 bytes)
	++tmpl->next_dataid;
	
	size_t datasz = 60 + scriptsz;
	unsigned char *data = malloc(datasz);
	if (!data)
		return 0;
	
	memcpy(&data[0],
		"\x01\0\0\0"  // txn ver
		"\x01"        // input count
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"  // prevout
			"\xff\xff\xff\xff"  // index (-1)
			"\0"                // scriptSig length (0; extranonce will bring up to 4)
			"\xff\xff\xff\xff"  // sequence
		"\x01"        // output count
		, 47);
	my_htole64(&data[47], tmpl->cbvalue);
	data[55] = scriptsz;
	memcpy(&data[56], script, scriptsz);
	memset(&data[56 + scriptsz], 0, 4);  // lock time
	
	struct blktxn_t *txn = calloc(1, sizeof(*tmpl->cbtxn));
	if (!tmpl->cbtxn)
	{
		free(data);
		return 0;
	}
	
	txn->data = data;
	txn->datasz = datasz;
	
	tmpl->cbtxn = txn;
	return tmpl->cbvalue;
}

static
bool build_merkle_root(unsigned char *mrklroot_out, blktemplate_t *tmpl, unsigned char *cbtxndata, size_t cbtxndatasz) {
	size_t hashcount = tmpl->txncount + 1;
	unsigned char hashes[(hashcount + 1) * 32];
	
	if (!dblsha256(&hashes[0], cbtxndata, cbtxndatasz))
		return false;
	for (unsigned long i = 0; i < tmpl->txncount; ++i)
		if (!dblsha256(&hashes[32 * (i + 1)], tmpl->txns[i].data, tmpl->txns[i].datasz))
			return false;
	
	while (hashcount > 1)
	{
		if (hashcount % 2)
		{
			memcpy(&hashes[32 * hashcount], &hashes[32 * (hashcount - 1)], 32);
			++hashcount;
		}
		for (size_t i = 0; i < hashcount; i += 2)
			// This is where we overlap input and output, on the first pair
			if (!dblsha256(&hashes[i / 2 * 32], &hashes[32 * i], 64))
				return false;
		hashcount /= 2;
	}
	
	memcpy(mrklroot_out, &hashes[0], 32);
	
	return true;
}

static const int cbScriptSigLen = 4 + 1 + 36;

static
bool _blkmk_append_cb(blktemplate_t *tmpl, void *vout, const void *append, size_t appendsz) {
	unsigned char *out = vout;
	unsigned char *in = tmpl->cbtxn->data;
	size_t insz = tmpl->cbtxn->datasz;
	
	if (in[cbScriptSigLen] > 100 - appendsz)
		return false;
	
	int cbPostScriptSig = cbScriptSigLen + 1 + in[cbScriptSigLen];
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
	
	return true;
}

ssize_t blkmk_append_coinbase_safe(blktemplate_t *tmpl, const void *append, size_t appendsz) {
	if (!(tmpl->mutations & (BMM_CBAPPEND | BMM_CBSET)))
		return -1;
	
	size_t datasz = tmpl->cbtxn->datasz;
	size_t availsz = 100 - sizeof(unsigned int) - tmpl->cbtxn->data[cbScriptSigLen];
	if (appendsz > availsz)
		return availsz;
	
	void *newp = realloc(tmpl->cbtxn->data, datasz + appendsz);
	if (!newp)
		return -2;
	
	tmpl->cbtxn->data = newp;
	if (!_blkmk_append_cb(tmpl, newp, append, appendsz))
		return -3;
	tmpl->cbtxn->datasz += appendsz;
	
	return availsz;
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
	
	if (!_blkmk_append_cb(tmpl, vout, &workid, sizeof(workid)))
		return false;
	
	*offs += insz + sizeof(workid);
	
	return true;
}

size_t blkmk_get_data(blktemplate_t *tmpl, void *buf, size_t bufsz, time_t usetime, int16_t *out_expire, unsigned int *out_dataid) {
	if (!(blkmk_time_left(tmpl, usetime) && blkmk_work_left(tmpl)))
		return 0;
	if (bufsz < 76)
		return 76;
	
	unsigned char *cbuf = buf;
	
	my_htole32(&cbuf[0], tmpl->version);
	memcpy(&cbuf[4], &tmpl->prevblk, 32);
	
	unsigned char cbtxndata[tmpl->cbtxn->datasz + sizeof(*out_dataid)];
	size_t cbtxndatasz = 0;
	*out_dataid = tmpl->next_dataid++;
	if (!_blkmk_extranonce(tmpl, cbtxndata, *out_dataid, &cbtxndatasz))
		return 0;
	if (!build_merkle_root(&cbuf[36], tmpl, cbtxndata, cbtxndatasz))
		return 0;
	
	blktime_t timehdr = tmpl->curtime + difftime(usetime, tmpl->_time_rcvd);
	if (timehdr > tmpl->maxtime)
		timehdr = tmpl->maxtime;
	my_htole32(&cbuf[68], timehdr);
	memcpy(&cbuf[72], &tmpl->diffbits, 4);
	// TODO: set *out_expire if provided
	
	// TEMPORARY HACK:
	memcpy(tmpl->_mrklroot, &cbuf[36], 32);
	
	return 76;
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
		return 1;
	return UINT_MAX - tmpl->next_dataid;
	return BLKMK_UNLIMITED_WORK_COUNT;
}

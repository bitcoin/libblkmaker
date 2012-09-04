#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <blkmaker.h>
#include <blktemplate.h>

static inline
void my_htole32(unsigned char *buf, uint32_t n) {
	buf[0] = (n >>  0) % 256;
	buf[1] = (n >>  8) % 256;
	buf[2] = (n >> 16) % 256;
	buf[3] = (n >> 24) % 256;
}


bool (*blkmk_sha256_impl)(void *, const void *, size_t) = NULL;

static
bool dblsha256(void *hash, const void *data, size_t datasz) {
	return blkmk_sha256_impl(hash, data, datasz) && blkmk_sha256_impl(hash, hash, 32);
}

static
bool build_merkle_root(unsigned char *mrklroot_out, blktemplate_t *tmpl) {
	if (!tmpl->cbtxn)
		return false;
	
	size_t hashcount = tmpl->txncount + 1;
	unsigned char hashes[(hashcount + 1) * 32];
	
	if (!dblsha256(&hashes[0], tmpl->cbtxn->data, tmpl->cbtxn->datasz))
		return false;
	for (int i = 0; i < tmpl->txncount; ++i)
		if (!dblsha256(&hashes[32 * (i + 1)], tmpl->txns[i].data, tmpl->txns[i].datasz))
			return false;
	
	while (hashcount > 1)
	{
		if (hashcount % 2)
		{
			memcpy(&hashes[32 * hashcount], &hashes[32 * (hashcount - 1)], 32);
			++hashcount;
		}
		for (int i = 0; i < hashcount; i += 2)
			// This is where we overlap input and output, on the first pair
			if (!dblsha256(&hashes[i / 2 * 32], &hashes[32 * i], 64))
				return false;
		hashcount /= 2;
	}
	
	memcpy(mrklroot_out, &hashes[0], 32);
	
	return true;
}

size_t blkmk_get_data(blktemplate_t *tmpl, void *buf, size_t bufsz, time_t usetime, int16_t *out_expire) {
	if (!(blkmk_time_left(tmpl, usetime) && blkmk_work_left(tmpl)))
		return 0;
	if (bufsz < 76)
		return 76;
	
	unsigned char *cbuf = buf;
	
	my_htole32(&cbuf[0], tmpl->version);
	memcpy(&cbuf[4], &tmpl->prevblk, 32);
	if (!build_merkle_root(&cbuf[36], tmpl))
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
	// TODO
	// TEMPORARY HACK
	return (tmpl->version && !tmpl->_mrklroot[0]) ? 1 : 0;
	return BLKMK_UNLIMITED_WORK_COUNT;
}

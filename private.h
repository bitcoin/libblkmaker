#ifndef BLKMK_PRIVATE_H
#define BLKMK_PRIVATE_H

#include <stdbool.h>
#include <string.h>

#include <blktemplate.h>

// blkmaker.c
extern bool _blkmk_dblsha256(void *hash, const void *data, size_t datasz);
extern bool blkmk_sample_data_(blktemplate_t *, uint8_t *, unsigned int dataid);
extern char *blkmk_assemble_submission2_(blktemplate_t *, const unsigned char *data, const void *extranonce, size_t extranoncesz, unsigned int dataid, blknonce_t nonce, bool foreign);

// hex.c
extern void _blkmk_bin2hex(char *out, const void *data, size_t datasz);
extern bool _blkmk_hex2bin(void *o, const char *x, size_t len);

// inline

// NOTE: This must return 0 for 0
static inline
int blkmk_flsl(unsigned long n)
{
	int i;
	for (i = 0; n; ++i)
		n >>= 1;
	return i;
}

static inline
uint16_t upk_u16le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint16_t)buf[offset+0]) <<    0)
	     | (((uint16_t)buf[offset+1]) <<    8);
}

static inline
uint32_t upk_u32le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint32_t)buf[offset+0]) <<    0)
	     | (((uint32_t)buf[offset+1]) <<    8)
	     | (((uint32_t)buf[offset+2]) << 0x10)
	     | (((uint32_t)buf[offset+3]) << 0x18);
}

static inline
uint64_t upk_u64le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint64_t)buf[offset+0]) <<    0)
	     | (((uint64_t)buf[offset+1]) <<    8)
	     | (((uint64_t)buf[offset+2]) << 0x10)
	     | (((uint64_t)buf[offset+3]) << 0x18)
	     | (((uint64_t)buf[offset+4]) << 0x20)
	     | (((uint64_t)buf[offset+5]) << 0x28)
	     | (((uint64_t)buf[offset+6]) << 0x30)
	     | (((uint64_t)buf[offset+7]) << 0x38);
}

#endif

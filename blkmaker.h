#ifndef BLKMAKER_H
#define BLKMAKER_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <blktemplate.h>

#define BLKMAKER_VERSION (4L)
#define BLKMAKER_MAX_BLOCK_VERSION (2)

extern bool (*blkmk_sha256_impl)(void *hash_out, const void *data, size_t datasz);

extern uint64_t blkmk_init_generation(blktemplate_t *, void *script, size_t scriptsz);
extern uint64_t blkmk_init_generation2(blktemplate_t *, void *script, size_t scriptsz, bool *out_newcb);
extern ssize_t blkmk_append_coinbase_safe(blktemplate_t *, const void *append, size_t appendsz);
extern bool _blkmk_extranonce(blktemplate_t *tmpl, void *vout, unsigned int workid, size_t *offs);
extern size_t blkmk_get_data(blktemplate_t *, void *buf, size_t bufsz, time_t usetime, int16_t *out_expire, unsigned int *out_dataid);
extern blktime_diff_t blkmk_time_left(const blktemplate_t *, time_t nowtime);
extern unsigned long blkmk_work_left(const blktemplate_t *);
#define BLKMK_UNLIMITED_WORK_COUNT  ULONG_MAX

extern size_t blkmk_address_to_script(void *out, size_t outsz, const char *addr);

#endif

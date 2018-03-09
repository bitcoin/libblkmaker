/*
 * Copyright 2012-2016 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#ifndef BLKTEMPLATE_H
#define BLKTEMPLATE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t blkheight_t;
typedef uint32_t libblkmaker_hash_t[8];
typedef libblkmaker_hash_t blkhash_t;
typedef libblkmaker_hash_t txnhash_t;
typedef uint32_t blktime_t;
typedef int16_t blktime_diff_t;
typedef uint32_t blknonce_t;

#define libblkmaker_blkheader_size (80)
#define libblkmaker_coinbase_size_minimum (4)
#define libblkmaker_coinbase_size_limit (100)

struct blktxn_t {
	unsigned char *data;
	size_t datasz;
	// NOTE: The byte order of hash is backward; use hash_ instead
	txnhash_t *hash;
	
	signed long dependscount;
	unsigned long *depends;
	
	int64_t fee_;
	bool required;
	int16_t sigops_;
	int32_t weight;
	
	txnhash_t *hash_;
	txnhash_t *txid;
};

struct blkaux_t {
	char *auxname;
	unsigned char *data;
	uint8_t datasz;
};

// BIP 23: Long Polling
struct blktmpl_longpoll_req {
	char *id;
	char *uri;
};


typedef enum {
	GBT_CBTXN    = 1 << 0,
	GBT_CBVALUE  = 1 << 1,
	GBT_WORKID   = 1 << 2,
	
	GBT_LONGPOLL = 1 << 3,  // BIP 22: Long Polling
	GBT_PROPOSAL = 1 << 4,  // BIP 23: Block Proposal
	GBT_SERVICE  = 1 << 5,  // BIP 23: Logical Services
	
	// BIP 23: Mutations
	BMM_CBAPPEND = 1 << 0x10,
	BMM_CBSET    = 1 << 0x11,
	BMM_GENERATE = 1 << 0x12,
	BMM_TIMEINC  = 1 << 0x13,
	BMM_TIMEDEC  = 1 << 0x14,
	BMM_TXNADD   = 1 << 0x15,
	BMM_PREVBLK  = 1 << 0x16,
	BMM_VERFORCE = 1 << 0x17,
	BMM_VERDROP  = 1 << 0x18,
	
	// BIP 23: Submission Abbreviation
	BMA_TXNHASH   = 1 << 0x19,
	BMAb_COINBASE = 1 << 0x1a,
	BMAb_TRUNCATE = 1 << 0x1b,
	BMAs_COINBASE = 1 << 0x1c,
	BMAs_MERKLE   = 1 << 0x1d,
	BMAs_TRUNCATE = 1 << 0x1e,
} gbt_capabilities_t;
#define GBT_CAPABILITY_COUNT  (0x1f)

extern const char *blktmpl_capabilityname(gbt_capabilities_t);
#define BLKTMPL_LONGEST_CAPABILITY_NAME  (16)
// NOTE: blktmpl_getcapability("time") yields a combination of gbt_capabilities_t
extern uint32_t blktmpl_getcapability(const char *);


typedef gbt_capabilities_t blkmutations_t;

struct blktmpl_vbassoc {
	char *name;
	uint8_t bitnum;
};

// WARNING: Do not allocate this (ABI is not guaranteed to remain fixed-size)
typedef struct {
	uint32_t version;
	unsigned char diffbits[4];
	blkheight_t height;
	blkhash_t prevblk;
	
	unsigned short sigoplimit;
	unsigned long sizelimit;
	
	unsigned long txncount;
	struct blktxn_t *txns;
	struct blktxn_t *cbtxn;
	uint64_t cbvalue;
	
	time_t _time_rcvd;
	blktime_t curtime;
	
	char *workid;
	
	// BIP 22: Long Polling
	struct blktmpl_longpoll_req lp;
	bool submitold;
	
	// BIP 23: Basic Pool Extensions
	int16_t expires;
	blkhash_t *target;
	
	// BIP 23: Mutations
	uint32_t mutations;
	blktime_t maxtime;
	blktime_diff_t maxtimeoff;
	blktime_t mintime;
	blktime_diff_t mintimeoff;
	
	// TEMPORARY HACK
	libblkmaker_hash_t *_mrklbranch;
	int _mrklbranchcount;
	unsigned int next_dataid;
	
	unsigned aux_count;
	struct blkaux_t *auxs;
	
	unsigned long txns_datasz;
	signed long txns_sigops;
	
	char **rules;
	bool unsupported_rule;
	struct blktmpl_vbassoc **vbavailable;
	uint32_t vbrequired;
	
	bool _bip141_sigops;
	bool _calculated_witness;
	libblkmaker_hash_t *_witnessmrklroot;
	int64_t weightlimit;
	int64_t txns_weight;
	
	bool has_cbvalue;
} blktemplate_t;

extern void blktxn_init(struct blktxn_t *);
extern void blktxn_clean(struct blktxn_t *);

extern blktemplate_t *blktmpl_create();
extern uint32_t blktmpl_addcaps(const blktemplate_t *);
extern const struct blktmpl_longpoll_req *blktmpl_get_longpoll(blktemplate_t *);
extern bool blktmpl_get_submitold(blktemplate_t *tmpl);
extern void blktmpl_free(blktemplate_t *);

#ifdef __cplusplus
}
#endif

#endif

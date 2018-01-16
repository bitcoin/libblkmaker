/*
 * Copyright 2012-2016 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include <blkmaker.h>
#include <blktemplate.h>

#include "private.h"

#ifndef JSON_INTEGER_IS_LONG_LONG
#	error "Jansson 2.0 with long long support required!"
#endif

json_t *blktmpl_request_jansson2(const uint32_t caps, const char * const lpid, const char * const * const rulelist) {
	json_t *req, *jcaps, *jstr, *reqf, *reqa;
	if (!(req = json_object()))
		return NULL;
	jstr = reqa = jcaps = NULL;
	if (!(reqf = json_object()))
		goto err;
	if (!(reqa = json_array()))
		goto err;
	if (!(jcaps = json_array()))
		goto err;
	for (int i = 0; i < GBT_CAPABILITY_COUNT; ++i)
		if (caps & (1 << i))
		{
			jstr = json_string(blktmpl_capabilityname(1 << i));
			if (!jstr)
				goto err;
			if (json_array_append_new(jcaps, jstr))
				goto err;
		}
	jstr = NULL;
	if (json_object_set_new(req, "capabilities", jcaps))
		goto err;
	jcaps = NULL;
	if (!(jstr = json_integer(0)))
		goto err;
	if (json_object_set_new(reqf, "id", jstr))
		goto err;
	if (!(jstr = json_integer(BLKMAKER_MAX_BLOCK_VERSION)))
		goto err;
	if (json_object_set_new(req, "maxversion", jstr))
		goto err;
	if (lpid)
	{
		if (!(jstr = json_string(lpid)))
			goto err;
		if (json_object_set_new(req, "longpollid", jstr))
			goto err;
	}
	jstr = NULL;
	
	// Add rules list
	if (!(jcaps = json_array())) {
		goto err;
	}
	for (const char * const *currule = rulelist; *currule; ++currule) {
		if (!(jstr = json_string(*currule))) {
			goto err;
		}
		if (json_array_append_new(jcaps, jstr)) {
			goto err;
		}
	}
	jstr = NULL;
	if (json_object_set_new(req, "rules", jcaps))
		goto err;
	jcaps = NULL;
	
	// Put together main JSON-RPC request Object
	if (!(jstr = json_string("getblocktemplate")))
		goto err;
	if (json_object_set_new(reqf, "method", jstr))
		goto err;
	jstr = NULL;
	if (json_array_append_new(reqa, req))
		goto err;
	req = NULL;
	if (json_object_set_new(reqf, "params", reqa))
		goto err;
	
	return reqf;

err:
	if (req  )  json_decref(req  );
	if (reqa )  json_decref(reqa );
	if (reqf )  json_decref(reqf );
	if (jcaps)  json_decref(jcaps);
	if (jstr )  json_decref(jstr );
	return NULL;
}

json_t *blktmpl_request_jansson(const uint32_t caps, const char * const lpid) {
	return blktmpl_request_jansson2(caps, lpid, blkmk_supported_rules);
}


#define my_hex2bin _blkmk_hex2bin

#define GET(key, type)  do {  \
	if (!(v = json_object_get(json, #key)))  \
		return "Missing '" #key "'";         \
	if (!json_is_ ## type(v))                \
		return "Wrong type for '" #key "'";  \
} while(0)

#define GETHEX(key, skey)  do {  \
	GET(key, string);                                                       \
	if (!my_hex2bin(tmpl->skey, json_string_value(v), sizeof(tmpl->skey)))  \
		return "Error decoding '" #key "'";                                 \
} while(0)

#define GETNUM(key, type)  do {  \
	GET(key, number);                       \
	const double tmpd = json_number_value(v);  \
	const type tmp = tmpd;  \
	if (tmpd != tmp) {  \
		return "Invalid number value for '" #key "'";  \
	}  \
	tmpl->key = tmp;  \
} while(0)

#define GETNUM_T(key, type)  do {  \
	GET(key, number);                       \
	const double tmpd = json_number_value(v);  \
	const type tmp = tmpd;  \
	/* This checks if it's merely being truncated, and tolerates it */ \
	if (tmpd != tmp && !((tmpd < 0) ? (tmpd < tmp && tmpd + 1 > tmp) : (tmpd > tmp && tmpd - 1 < tmp))) {  \
		return "Invalid number value for '" #key "'";  \
	}  \
	tmpl->key = tmp;  \
} while(0)

#define GETNUM_O2(key, skey, type)  do {  \
	if ((v = json_object_get(json, #skey)) && json_is_number(v)) {  \
		const double tmpd = json_number_value(v);  \
		const type tmp = tmpd;  \
		if (tmpd == tmp) {  \
			tmpl->key = tmp;  \
		}  \
	}  \
} while(0)

#define GETNUM_O(key, type)  GETNUM_O2(key, key, type)

#define GETNUM_OT(key, type)  do {  \
	if ((v = json_object_get(json, #key)) && json_is_number(v)) {  \
		const double tmpd = json_number_value(v);  \
		const type tmp = tmpd;  \
		/* This checks if it's merely being truncated, and tolerates it */ \
		if (tmpd == tmp || ((tmpd < 0) ? (tmpd < tmp && tmpd + 1 > tmp) : (tmpd > tmp && tmpd - 1 < tmp))) {  \
			tmpl->key = tmp;  \
		}  \
	}  \
} while(0)

#define GETSTR(key, skey)  do {  \
	if ((v = json_object_get(json, #key)) && json_is_string(v))  \
		if (!(tmpl->skey = strdup(json_string_value(v))))  \
			return "Error copying '" #key "'";  \
} while(0)

#define GETBOOL(key, skey, def)  do {  \
	if ((v = json_object_get(json, #key)) && json_is_boolean(v))  \
		tmpl->skey = json_is_true(v);  \
	else  \
	if (def)  \
		tmpl->skey = true;  \
} while(0)

static void my_flip(void *, size_t);

static
const char *parse_txn(struct blktxn_t *txn, json_t *txnj, size_t my_tx_index) {
	json_t *vv;
	
	blktxn_init(txn);
	
	if (!((vv = json_object_get(txnj, "data")) && json_is_string(vv)))
		return "Missing or invalid type for transaction data";
	const char *hexdata = json_string_value(vv);
	size_t datasz = strlen(hexdata) / 2;
	txn->data = malloc(datasz);
	txn->datasz = datasz;
	if (!my_hex2bin(txn->data, hexdata, datasz))
		return "Error decoding transaction data";
	
	if ((vv = json_object_get(txnj, "hash")) && json_is_string(vv))
	{
		hexdata = json_string_value(vv);
		txn->hash_ = malloc(sizeof(*txn->hash_));
		if (!my_hex2bin(*txn->hash_, hexdata, sizeof(*txn->hash_)))
		{
			free(txn->hash_);
			txn->hash_ = NULL;
		}
		else
			my_flip(*txn->hash_, sizeof(*txn->hash_));
	}
	
	if ((vv = json_object_get(txnj, "txid")) && json_is_string(vv)) {
		hexdata = json_string_value(vv);
		txn->txid = malloc(sizeof(*txn->txid));
		if (!my_hex2bin(*txn->txid, hexdata, sizeof(*txn->txid))) {
			return "Error decoding txid field";
		} else {
			my_flip(*txn->txid, sizeof(*txn->txid));
		}
	}
	
	txn->weight = -1;
	if ((vv = json_object_get(txnj, "weight")) && json_is_number(vv)) {
		const double f = json_number_value(txnj);
		const int32_t i32 = f;
		if (f == i32) {
			txn->weight = i32;
		}
	}
	
	if ((vv = json_object_get(txnj, "depends")) && json_is_array(vv)) {
		size_t depcount = json_array_size(vv);
		if (depcount <= LONG_MAX) {
			json_t *v;
			long i;
			double f;
			unsigned long ul;
			
			txn->depends = malloc(sizeof(*txn->depends) * depcount);
			for (i = 0; i < depcount; ++i) {
				v = json_array_get(vv, i);
				if (!json_is_number(v)) {
					break;
				}
				f = json_number_value(v);
				ul = f;
				if (f != ul || ul >= my_tx_index) {
					// Out of range for storage type, fractional number, forward dependency, etc
					break;
				}
				txn->depends[i] = ul;
			}
			if (i != depcount) {
				// We failed somewhere
				free(txn->depends);
				txn->depends = NULL;
			} else {
				// Success, finish up with storing the count
				txn->dependscount = depcount;
			}
		}
	}
	
	if ((vv = json_object_get(txnj, "fee")) && json_is_number(vv)) {
		double f;
		int64_t i64;
		
		f = json_number_value(vv);
		i64 = f;
		if (i64 == f && i64 >= 0) {
			txn->fee_ = i64;
		}
	}
	
	if ((vv = json_object_get(txnj, "required")) && json_is_true(vv)) {
		txn->required = true;
	}
	
	if ((vv = json_object_get(txnj, "sigops")) && json_is_number(vv)) {
		const double f = json_number_value(vv);
		int16_t i16 = f;
		if (i16 == f && i16 >= 0) {
			txn->sigops_ = i16;
		}
	}
	
	return NULL;
}

static
void my_flip(void *data, size_t datasz) {
	char *cdata = (char*)data;
	--datasz;
	size_t hds = datasz / 2;
	for (size_t i = 0; i <= hds; ++i)
	{
		int altp = datasz - i;
		char c = cdata[i];
		cdata[i] = cdata[altp];
		cdata[altp] = c;
	}
}

const char *blktmpl_add_jansson(blktemplate_t *tmpl, const json_t *json, time_t time_rcvd) {
	if (tmpl->version)
		return "Template already populated (combining not supported)";
	
	json_t *v, *v2;
	const char *s;
	
	if ((v = json_object_get(json, "result")))
	{
		json_t *je;
		if ((je = json_object_get(json, "error")) && !json_is_null(je))
			return "JSON result is error";
		json = v;
	}
	
	GETHEX(bits, diffbits);
	my_flip(tmpl->diffbits, 4);
	GETNUM_T(curtime, blktime_t);
	GETNUM(height, blkheight_t);
	GETHEX(previousblockhash, prevblk);
	my_flip(tmpl->prevblk, 32);
	GETNUM_O(sigoplimit, unsigned short);
	GETNUM_O(sizelimit, unsigned long);
	GETNUM_O(weightlimit, int64_t);
	GETNUM(version, uint32_t);
	
	if ((v = json_object_get(json, "mutable")) && json_is_array(v))
	{
		for (size_t i = json_array_size(v); i--; )
		{
			v2 = json_array_get(v, i);
			if (!json_is_string(v2))
				continue;
			tmpl->mutations |= blktmpl_getcapability(json_string_value(v2));
		}
	}
	
	if ((tmpl->version & 0xe0000000) == 0x20000000 && (v = json_object_get(json, "vbavailable")) && json_is_object(v) && (v = json_object_get(json, "rules")) && json_is_array(v)) {
		// calloc so that a failure doesn't result in freeing a random pointer
		size_t n = json_array_size(v);
		tmpl->rules = calloc(n + 1, sizeof(*tmpl->rules));
		for (size_t i = 0; i < n; ++i) {
			v2 = json_array_get(v, i);
			if (!json_is_string(v2)) {
				return "Non-String data in template rules list";
			}
			s = json_string_value(v2);
			if (s[0] == '!') {
				++s;
				if (!blkmk_supports_rule(s)) {
					return "Unsupported rule strictly required by template";
				}
			} else {
				if (!blkmk_supports_rule(s)) {
					tmpl->unsupported_rule = true;
				}
			}
			tmpl->rules[i] = strdup(s);
			if (!tmpl->rules[i]) {
				return "Memory allocation error parsing rules";
			}
			if (!strcmp(s, "segwit")) {
				tmpl->_bip141_sigops = true;
			}
		}
		
		v = json_object_get(json, "vbavailable");
		n = json_object_size(v);
		tmpl->vbavailable = calloc(n + 1, sizeof(*tmpl->vbavailable));
		struct blktmpl_vbassoc **cur_vbassoc = tmpl->vbavailable;
		for (void *iter = json_object_iter(v); iter; (iter = json_object_iter_next(v, iter)), ++cur_vbassoc) {
			v2 = json_object_iter_value(iter);
			if (!json_is_number(v2)) {
				return "Invalid type for vbavailable bit";
			}
			double bitnum = json_number_value(v2);
			if (bitnum < 0 || bitnum > 28 || (unsigned)bitnum != bitnum) {
				return "Invalid bit number in vbavailable";
			}
			*cur_vbassoc = malloc(sizeof(**cur_vbassoc));
			if (!*cur_vbassoc) {
				return "Memory allocation error for struct blktmpl_vbassoc";
			}
			**cur_vbassoc = (struct blktmpl_vbassoc){
				.name = strdup(json_object_iter_key(iter)),
				.bitnum = bitnum,
			};
			if (!(*cur_vbassoc)->name) {
				return "Memory allocation error for vbavailable name";
			}
		}
		
		v = json_object_get(json, "vbrequired");
		if (v && json_is_number(v)) {
			double tmpd = json_number_value(v);
			tmpl->vbrequired = tmpd;
			if (tmpl->vbrequired != tmpd) {
				return "Unparsable vbrequired";
			}
		}
	}
	else
	if (tmpl->version > BLKMAKER_MAX_PRERULES_BLOCK_VERSION || (tmpl->version >= 2 && !tmpl->height))
	{
		if (tmpl->mutations & BMM_VERDROP)
			tmpl->version = tmpl->height ? BLKMAKER_MAX_PRERULES_BLOCK_VERSION : 1;
		else
		if (!(tmpl->mutations & BMM_VERFORCE))
			return "Unrecognized block version, and not allowed to reduce or force it";
	}
	
	GETNUM_O2(cbvalue, coinbasevalue, uint64_t);
	
	GETSTR(workid, workid);
	
	GETNUM_OT(expires, int16_t);
	GETNUM_OT(maxtime, blktime_t);
	GETNUM_OT(maxtimeoff, blktime_diff_t);
	GETNUM_OT(mintime, blktime_t);
	GETNUM_OT(mintimeoff, blktime_diff_t);
	
	GETSTR(longpollid, lp.id);
	GETSTR(longpolluri, lp.uri);
	GETBOOL(submitold, submitold, true);
	
	v = json_object_get(json, "transactions");
	size_t txns = tmpl->txncount = json_array_size(v);
	tmpl->txns = calloc(txns, sizeof(*tmpl->txns));
	tmpl->txns_datasz = 0;
	tmpl->txns_sigops = 0;
	tmpl->txns_weight = 0;
	for (size_t i = 0; i < txns; ++i)
	{
		struct blktxn_t * const txn = &tmpl->txns[i];
		if ((s = parse_txn(txn, json_array_get(v, i), i + 1))) {
			return s;
		}
		tmpl->txns_datasz += txn->datasz;
		if (tmpl->txns_sigops == -1) {
			;  // Impossible to tally the unknown
		} else if (txn->sigops_ == -1) {
			tmpl->txns_sigops = -1;
		} else {
			tmpl->txns_sigops += txn->sigops_;
		}
		if (tmpl->txns_weight == -1) {
			;  // Impossible to tally the unknown
		} else if (txn->weight == -1) {
			tmpl->txns_weight = -1;
		} else {
			tmpl->txns_weight += txn->weight;
		}
	}
	
	if ((v = json_object_get(json, "coinbasetxn")) && json_is_object(v))
	{
		tmpl->cbtxn = calloc(1, sizeof(*tmpl->cbtxn));
		if ((s = parse_txn(tmpl->cbtxn, v, 0)))
			return s;
	} else if (!tmpl->cbvalue) {
		return "Missing either coinbasetxn or coinbasevalue";
	}
	
	if ((v = json_object_get(json, "coinbaseaux")) && json_is_object(v))
	{
		tmpl->aux_count = json_object_size(v);
		tmpl->auxs = calloc(tmpl->aux_count, sizeof(*tmpl->auxs));
		unsigned i = 0;
		for (void *iter = json_object_iter(v); iter; (iter = json_object_iter_next(v, iter)), ++i)
		{
			v2 = json_object_iter_value(iter);
			s = json_string_value(v2);
			if (!s)
				continue;
			size_t sz = strlen(s) / 2;
			tmpl->auxs[i] = (struct blkaux_t){
				.auxname = strdup(json_object_iter_key(iter)),
				.data = malloc(sz),
				.datasz = sz,
			};
			if (!my_hex2bin(tmpl->auxs[i].data, s, sz)) {
				return "Error decoding 'coinbaseaux' data";
			}
		}
	}
	
	if ((v = json_object_get(json, "target")) && json_is_string(v))
	{
		tmpl->target = malloc(sizeof(*tmpl->target));
		if (!my_hex2bin(tmpl->target, json_string_value(v), sizeof(*tmpl->target)))
			return "Error decoding 'target'";
	}
	
	tmpl->_time_rcvd = time_rcvd;
	
	return NULL;
}

json_t *blktmpl_propose_jansson(blktemplate_t * const tmpl, const uint32_t caps, const bool foreign) {
	json_t *jreq = blktmpl_request_jansson(caps, NULL), *ja = NULL, *jparams;
	if (!(jreq && json_is_object(jreq)))
		goto err;
	
	jparams = json_array_get(json_object_get(jreq, "params"), 0);
	if (!(jparams && json_is_object(jparams)))
		goto err;
	
	if (!(ja = json_string("proposal")))
		goto err;
	if (json_object_set_new(jparams, "mode", ja))
		goto err;
	
	if (tmpl->workid && !foreign)
	{
		if (!(ja = json_string(tmpl->workid)))
			goto err;
		if (json_object_set_new(jparams, "workid", ja))
			goto err;
	}
	ja = NULL;
	
	unsigned int dataid = (tmpl->mutations & (BMM_CBAPPEND | BMM_CBSET) ? 1 : 0);
	
	uint8_t sdata[0x4c];
	if (!blkmk_sample_data_(tmpl, sdata, dataid))
		goto err;
	char *blkhex = blkmk_assemble_submission2_(tmpl, sdata, NULL, 0, dataid, 0, foreign);
	if (!blkhex)
		goto err;
	if (!(ja = json_string(blkhex)))
		goto err;
	free(blkhex);
	if (json_object_set_new(jparams, "data", ja))
		goto err;
	
	return jreq;

err:
	if (jreq)  json_decref(jreq);
	if (ja)    json_decref(ja);
	return NULL;
}

static
json_t *_blkmk_submit_jansson(blktemplate_t *tmpl, const unsigned char *data, const void * const extranonce, const size_t extranoncesz, unsigned int dataid, blknonce_t nonce, bool foreign) {
	char *blkhex = blkmk_assemble_submission2_(tmpl, data, extranonce, extranoncesz, dataid, nonce, foreign);
	if (!blkhex)
		return NULL;
	
	json_t *rv = json_array(), *ja, *jb;
	jb = NULL;
	ja = json_string(blkhex);
	free(blkhex);
	if (!ja)
		goto err;
	if (json_array_append_new(rv, ja))
		goto err;
	if (!(ja = json_object()))
		goto err;
	if (tmpl->workid && !foreign)
	{
		if (!(jb = json_string(tmpl->workid)))
			goto err;
		if (json_object_set_new(ja, "workid", jb))
			goto err;
		jb = NULL;
	}
	if (json_array_append_new(rv, ja))
		goto err;
	
	if (!(ja = json_object()))
		goto err;
	if (!(jb = json_integer(0)))
		goto err;
	if (json_object_set_new(ja, "id", jb))
		goto err;
	if (!(jb = json_string("submitblock")))
		goto err;
	if (json_object_set_new(ja, "method", jb))
		goto err;
	jb = NULL;
	if (json_object_set_new(ja, "params", rv))
		goto err;
	
	return ja;

err:
	json_decref(rv);
	if (ja)  json_decref(ja);
	if (jb)  json_decref(jb);
	return NULL;
}

json_t *blkmk_submit_jansson(blktemplate_t *tmpl, const unsigned char *data, unsigned int dataid, blknonce_t nonce) {
	return _blkmk_submit_jansson(tmpl, data, NULL, 0, dataid, nonce, false);
}

json_t *blkmk_submit_foreign_jansson(blktemplate_t *tmpl, const unsigned char *data, unsigned int dataid, blknonce_t nonce) {
	return _blkmk_submit_jansson(tmpl, data, NULL, 0, dataid, nonce, true);
}

json_t *blkmk_submitm_jansson(blktemplate_t * const tmpl, const unsigned char *data, const void * const extranonce, const size_t extranoncesz, const blknonce_t nonce, const bool foreign) {
	return _blkmk_submit_jansson(tmpl, data, extranonce, extranoncesz, 0, nonce, foreign);
}

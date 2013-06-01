/*
 * Copyright 2012 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <jansson.h>

#include <blkmaker.h>
#include <blktemplate.h>

#ifndef JSON_INTEGER_IS_LONG_LONG
#	error "Jansson 2.0 with long long support required!"
#endif

json_t *blktmpl_request_jansson(gbt_capabilities_t caps, const char *lpid) {
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


static bool my_hex2bin(void *o, const char *x, size_t len) {
	unsigned char *oc = o;
	unsigned char c, hc = 0x10;
	len *= 2;
	while (len)
	{
		switch (x[0]) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			c = x[0] - '0';
			break;
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
			c = x[0] - 'A' + 10;
			break;
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			c = x[0] - 'a' + 10;
			break;
		default:
			return false;
		}
		++x;
		if (hc < 0x10)
		{
			(oc++)[0] = (hc << 4) | c;
			hc = 0x10;
		}
		else
			hc = c;
		--len;
	}
	return !x[0];
}

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

#define GETNUM(key)  do {  \
	GET(key, number);                       \
	tmpl->key = json_integer_value(v);      \
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

static
const char *parse_txn(struct blktxn_t *txn, json_t *txnj) {
	json_t *vv;
	
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
		txn->hash = malloc(sizeof(*txn->hash));
		if (!my_hex2bin(*txn->hash, hexdata, sizeof(*txn->hash)))
		{
			free(txn->hash);
			txn->hash = NULL;
		}
	}
	
	// TODO: dependcount/depends, fee, required, sigops
	
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
		return false;
	
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
	GETNUM(curtime);
	GETNUM(height);
	GETHEX(previousblockhash, prevblk);
	my_flip(tmpl->prevblk, 32);
	if (json_object_get(json, "sigoplimit"))
		GETNUM(sigoplimit);
	if (json_object_get(json, "sizelimit"))
		GETNUM(sizelimit);
	GETNUM(version);
	
	if ((v = json_object_get(json, "coinbasevalue")) && json_is_number(v))
		tmpl->cbvalue = json_integer_value(v);
	
	GETSTR(workid, workid);
	
	if (json_object_get(json, "expires"))
		GETNUM(expires);
	
	GETSTR(longpollid, lp.id);
	GETSTR(longpolluri, lp.uri);
	GETBOOL(submitold, submitold, true);
	
	v = json_object_get(json, "transactions");
	size_t txns = tmpl->txncount = json_array_size(v);
	tmpl->txns = calloc(txns, sizeof(*tmpl->txns));
	for (size_t i = 0; i < txns; ++i)
		if ((s = parse_txn(&tmpl->txns[i], json_array_get(v, i))))
			return s;
	
	if ((v = json_object_get(json, "coinbasetxn")) && json_is_object(v))
	{
		tmpl->cbtxn = calloc(1, sizeof(*tmpl->cbtxn));
		if ((s = parse_txn(tmpl->cbtxn, v)))
			return s;
	}
	
	// TODO: coinbaseaux
	
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
	
	if (tmpl->version > 2 || (tmpl->version == 2 && !tmpl->height))
	{
		if (tmpl->mutations & BMM_VERDROP)
			tmpl->version = tmpl->height ? 2 : 1;
		else
		if (!(tmpl->mutations & BMM_VERFORCE))
			return "Unrecognized block version, and not allowed to reduce or force it";
	}
	
	tmpl->_time_rcvd = time_rcvd;
	
	return NULL;
}

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

static
void my_bin2hex(char *out, const void *data, size_t datasz) {
	const unsigned char *datac = data;
	static char hex[] = "0123456789abcdef";
	out[datasz * 2] = '\0';
	for (size_t i = 0; i < datasz; ++i)
	{
		out[ i*2   ] = hex[datac[i] >> 4];
		out[(i*2)+1] = hex[datac[i] & 15];
	}
}

json_t *blkmk_submit_jansson(blktemplate_t *tmpl, const unsigned char *data, unsigned int dataid, blknonce_t nonce) {
	unsigned char blk[80 + 8 + 1000000];
	memcpy(blk, data, 76);
	*(uint32_t*)(&blk[76]) = htonl(nonce);
	size_t offs = 80;
	
	if (!(tmpl->mutations & BMAb_TRUNCATE && !dataid))
	{
		offs += varintEncode(&blk[offs], 1 + tmpl->txncount);
		
		if (!_blkmk_extranonce(tmpl, &blk[offs], dataid, &offs))
			return NULL;
		
		if (!(tmpl->mutations & BMAb_COINBASE))
			for (unsigned long i = 0; i < tmpl->txncount; ++i)
			{
				memcpy(&blk[offs], tmpl->txns[i].data, tmpl->txns[i].datasz);
				offs += tmpl->txns[i].datasz;
			}
	}
	
	char blkhex[(offs * 2) + 1];
	my_bin2hex(blkhex, blk, offs);
	
	json_t *rv = json_array(), *ja, *jb;
	jb = NULL;
	if (!(ja = json_string(blkhex)))
		goto err;
	if (json_array_append_new(rv, ja))
		goto err;
	if (!(ja = json_object()))
		goto err;
	if (tmpl->workid)
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

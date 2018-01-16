/*
 * Copyright 2016 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <gcrypt.h>

#include "blktemplate.h"
#include "blkmaker.h"
#include "blkmaker_jansson.h"

static bool my_sha256(void *digest, const void *buffer, size_t length) {
	gcry_md_hash_buffer(GCRY_MD_SHA256, digest, buffer, length);
	return true;
}

static bool bad_sha256(void *digest, const void *buffer, size_t length) {
	return false;
}

static void capabilityname_test() {
	for (unsigned int i = 0; i < GBT_CAPABILITY_COUNT; ++i) {
		const gbt_capabilities_t capid = (1 << i);
		const char * const capname = blktmpl_capabilityname(capid);
		if (!capname) {
			continue;
		}
		const size_t strlen_capname = strlen(capname);
		assert(strlen_capname > 0);
		assert(strlen_capname <= BLKTMPL_LONGEST_CAPABILITY_NAME);
		assert(blktmpl_getcapability(capname) == capid);
	}
	assert(!blktmpl_getcapability("foo"));
	assert(!blktmpl_capabilityname((uint32_t)1 << GBT_CAPABILITY_COUNT));
}

static void blktxn_test(const int c) {
	struct blktxn_t * const txn = malloc(sizeof(*txn));
	memset(txn, c, sizeof(*txn));
	blktxn_init(txn);
	blktxn_clean(txn);
	free(txn);
}

static bool caps_includes(const uint32_t caps, const uint32_t expected_caps) {
	return (caps & expected_caps) == expected_caps;
}

static void blktmpl_test() {
	blktemplate_t * const tmpl = blktmpl_create();
	
	{
		static const uint32_t expected_fresh_caps = GBT_CBTXN | GBT_WORKID | BMM_TIMEINC | BMM_CBAPPEND | BMM_VERFORCE | BMM_VERDROP | BMAb_COINBASE | BMAb_TRUNCATE;
		assert(caps_includes(blktmpl_addcaps(tmpl), expected_fresh_caps));
	}
	
	assert(!tmpl->version);
	assert(!blktmpl_get_longpoll(tmpl));
	assert(!blktmpl_get_submitold(tmpl));
	
	blktmpl_free(tmpl);
}

static bool json_are_equal(json_t * const ja, json_t * const jb) {
	char *sa, *sb;
	sa = json_dumps(ja, JSON_COMPACT | JSON_SORT_KEYS);
	sb = json_dumps(jb, JSON_COMPACT | JSON_SORT_KEYS);
	const bool rv = !strcmp(sa, sb);
	free(sa);
	free(sb);
	return rv;
}

static void rulecompare(json_t * const jb, const char * const * const rulelist) {
	const size_t z = json_array_size(jb);
	const char *sa;
	json_t *jc;
	
	for (size_t i = 0; i < z; ++i) {
		assert((jc = json_array_get(jb, i)));
		assert((sa = json_string_value(jc)));
		assert(!strcmp(sa, rulelist[i]));
	}
	assert(!rulelist[z]);
}

static void check_request(json_t * const ja, const char * const * const rulelist, uint32_t * const out_caps) {
	const char *sa;
	json_t *jb, *jc;
	
	assert(json_object_get(ja, "id"));
	assert((jb = json_object_get(ja, "method")));
	assert((sa = json_string_value(jb)));
	assert(!strcmp(sa, "getblocktemplate"));
	assert((jb = json_object_get(ja, "params")));
	assert(json_is_array(jb));
	assert(json_array_size(jb) >= 1);
	jc = json_array_get(jb, 0);
	assert(json_is_object(jc));
	assert((jb = json_object_get(jc, "maxversion")));
	assert(json_number_value(jb) == BLKMAKER_MAX_BLOCK_VERSION);
	assert((jb = json_object_get(jc, "rules")));
	assert(json_is_array(jb));
	rulecompare(jb, rulelist);
	if (out_caps) {
		*out_caps = 0;
		if ((jb = json_object_get(jc, "capabilities")) && json_is_array(jb)) {
			const size_t z = json_array_size(jb);
			for (size_t i = 0; i < z; ++i) {
				assert((jc = json_array_get(jb, i)));
				assert((sa = json_string_value(jc)));
				uint32_t capid = blktmpl_getcapability(sa);
				assert(capid);
				*out_caps |= capid;
			}
		}
	}
}

static void blktmpl_request_jansson_test_old() {
	blktemplate_t * const tmpl = blktmpl_create();
	json_t *ja, *jb;
	
	ja = blktmpl_request_jansson2(0, NULL, blkmk_supported_rules);
	jb = blktmpl_request_jansson(0, NULL);
	assert(json_are_equal(ja, jb));
	json_decref(jb);
	
	check_request(ja, blkmk_supported_rules, NULL);
	
	json_decref(ja);
	blktmpl_free(tmpl);
}

static void blktmpl_request_jansson_test_custom_rulelist() {
	blktemplate_t * const tmpl = blktmpl_create();
	json_t *ja;
	const char *custom_rulelist[] = {
		"abc",
		"xyz",
		NULL
	};
	
	ja = blktmpl_request_jansson2(0, NULL, custom_rulelist);
	check_request(ja, custom_rulelist, NULL);
	
	json_decref(ja);
	blktmpl_free(tmpl);
}

static void blktmpl_request_jansson_test_custom_caps_i(json_t * const ja, const uint32_t test_caps) {
	uint32_t caps;
	check_request(ja, blkmk_supported_rules, &caps);
	assert(caps == test_caps);
	json_decref(ja);
}

static void blktmpl_request_jansson_test_custom_caps() {
	blktemplate_t * const tmpl = blktmpl_create();
	json_t *ja;
	uint32_t test_caps = GBT_SERVICE | GBT_LONGPOLL;
	
	ja = blktmpl_request_jansson2(test_caps, NULL, blkmk_supported_rules);
	blktmpl_request_jansson_test_custom_caps_i(ja, test_caps);
	
	test_caps |= blktmpl_addcaps(tmpl);
	ja = blktmpl_request_jansson2(test_caps, NULL, blkmk_supported_rules);
	blktmpl_request_jansson_test_custom_caps_i(ja, test_caps);
	
	blktmpl_free(tmpl);
}

static void blktmpl_request_jansson_test_longpoll() {
	blktemplate_t * const tmpl = blktmpl_create();
	static const char * const lpid = "mylpid00";
	const char *sa;
	json_t *ja, *jb, *jc;
	
	ja = blktmpl_request_jansson2(0, lpid, blkmk_supported_rules);
	check_request(ja, blkmk_supported_rules, NULL);
	
	jb = json_array_get(json_object_get(ja, "params"), 0);
	assert((jc = json_object_get(jb, "longpollid")));
	assert((sa = json_string_value(jc)));
	assert(!strcmp(sa, lpid));
	
	json_decref(ja);
	blktmpl_free(tmpl);
}

static const char *blktmpl_add_jansson_str(blktemplate_t * const tmpl, const char * const s, const time_t time_rcvd) {
	json_t * const j = json_loads(s, 0, NULL);
	assert(j);
	const char * const rv = blktmpl_add_jansson(tmpl, j, time_rcvd);
	json_decref(j);
	return rv;
}

static const time_t simple_time_rcvd = 0x777;

static void blktmpl_jansson_simple() {
	blktemplate_t *tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	assert(blktmpl_addcaps(tmpl) == 0);  // Until we support merging templates
	assert(tmpl->version == 2);
	assert(tmpl->height == 3);
	assert(!memcmp(tmpl->diffbits, "\xff\xff\0\x1d", 4));
	assert(tmpl->curtime == 777);
	for (int i = 0; i < 7; ++i) {
		assert(tmpl->prevblk[i] == 0x77777777);
	}
	assert(!tmpl->prevblk[7]);
	assert(tmpl->cbvalue == 512);
	
	// Check clear values
	assert(tmpl->txncount == 0);
	assert(tmpl->txns_datasz == 0);
	assert(tmpl->txns_sigops == 0);
	assert(!tmpl->cbtxn);
	assert(!tmpl->workid);
	assert(!blktmpl_get_longpoll(tmpl));
	assert(blktmpl_get_submitold(tmpl));
	assert(!tmpl->target);
	assert(!tmpl->mutations);
	assert(tmpl->aux_count == 0);
	assert(!tmpl->rules);
	assert(!tmpl->unsupported_rule);
	assert(!tmpl->vbavailable);
	assert(!tmpl->vbrequired);
	
	// Check reasonable default ranges
	assert(tmpl->sigoplimit >= 20000);
	assert(tmpl->sizelimit >= 1000000);
	assert(tmpl->expires >= 60);
	assert(tmpl->maxtime >= tmpl->curtime + 60);
	assert(tmpl->maxtimeoff >= 60);
	assert(tmpl->mintime <= tmpl->curtime - 60);
	assert(tmpl->mintimeoff <= -60);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(blktmpl_add_jansson_str(tmpl, "{\"height\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"curtime\":777,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"bits\":\"1d00ffff\",\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"coinbasevalue\":512}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\"}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"previousblockhash\":\"0??0000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2,\"height\":3,\"bits\":\"1d00ffff\",\"curtime\":777,\"previousblockhash\":\"00000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512}", simple_time_rcvd));
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_bip22_required() {
	blktemplate_t * const tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaAaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62F2cdd80937c9c0857cEDeC005b11d3B902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbaseaux\":{\"dummy\":\"deadbeef\"},\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\"}", simple_time_rcvd));
	assert(tmpl->version == 3);
	assert(tmpl->height == 4);
	assert(!memcmp(tmpl->diffbits, "\xff\x7f\0\x1d", 4));
	assert(tmpl->curtime == 877);
	for (int i = 0; i < 7; ++i) {
		assert(tmpl->prevblk[i] == 0xa7777777);
	}
	assert(!tmpl->prevblk[7]);
	assert(tmpl->cbvalue == 640);
	assert(tmpl->sigoplimit == 100);
	assert(tmpl->sizelimit == 1000);
	assert(tmpl->txncount == 3);
	assert(tmpl->txns);
	assert(tmpl->txns[0].data);
	assert(tmpl->txns[0].datasz == 57);
	assert(!memcmp(tmpl->txns[0].data, "\x01\0\0\0\x01\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\xaa\xaa\xaa\xaa\0\x22\x22\x22\x22\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[0].dependscount == -1);
	assert(tmpl->txns[0].fee_ == -1);
	assert(tmpl->txns[0].required);
	assert(tmpl->txns[0].sigops_ == -1);
	assert(tmpl->txns[1].data);
	assert(tmpl->txns[1].datasz == 57);
	assert(!memcmp(tmpl->txns[1].data, "\x01\0\0\0\x01\x1c\x69\xf2\x12\xe6\x2f\x2c\xdd\x80\x93\x7c\x9c\x08\x57\xce\xde\xc0\x05\xb1\x1d\x3b\x90\x2d\x21\0\x7c\x93\x2c\x1c\x7c\xd2\x0f\0\0\0\0\0\x44\x44\x44\x44\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[1].dependscount == 1);
	assert(tmpl->txns[1].depends);
	assert(tmpl->txns[1].depends[0] == 1);
	assert(tmpl->txns[1].fee_ == 12);
	assert(!tmpl->txns[1].required);
	assert(tmpl->txns[1].sigops_ == 4);
	assert(!memcmp(tmpl->txns[1].hash_, "\x8d\x7e\x01\x67\x43\x9d\xab\x18\x6e\x86\xf9\x13\xb2\x7f\x3a\xc2\x15\x67\xdd\x4e\xde\xf8\x9a\xa8\x01\x64\x99\x67\x8b\x1a\xda\x8e", 32));
	assert(tmpl->txns[2].data);
	assert(tmpl->txns[2].datasz == 57);
	assert(!memcmp(tmpl->txns[2].data, "\x01\0\0\0\x01\0\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\xaa\xaa\xaa\xaa\0\x55\x55\x55\x55\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[2].dependscount == -1);
	assert(tmpl->txns[2].fee_ == -1);
	assert(!tmpl->txns[2].required);
	assert(tmpl->txns[2].sigops_ == -1);
	assert(tmpl->cbtxn->data);
	assert(tmpl->cbtxn->datasz == 64);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x07\x01\x04\x04\xde\xad\xbe\xef\x33\x33\x33\x33\x01\0\x10\0\0\x01\x51\0\0\0\0", 64));
	assert(tmpl->aux_count == 1);
	assert(tmpl->auxs);
	assert(tmpl->auxs[0].auxname);
	assert(!strcmp(tmpl->auxs[0].auxname, "dummy"));
	assert(tmpl->auxs[0].datasz == 4);
	assert(!memcmp(tmpl->auxs[0].data, "\xde\xad\xbe\xef", 4));
	assert(tmpl->workid);
	assert(!strcmp(tmpl->workid, "mywork"));
	assert(blktmpl_get_submitold(tmpl));
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_bip22_longpoll() {
	blktemplate_t *tmpl = blktmpl_create();
	const struct blktmpl_longpoll_req *lp;
	
	assert(!blktmpl_get_longpoll(tmpl));
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"longpollid\":\"mylpid\"}", simple_time_rcvd));
	lp = blktmpl_get_longpoll(tmpl);
	assert(lp->id);
	assert(!strcmp(lp->id, "mylpid"));
	assert(!lp->uri);
	assert(blktmpl_get_submitold(tmpl));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"longpollid\":\"myLPid\",\"longpolluri\":\"/LP\",\"submitold\":false}", simple_time_rcvd));
	lp = blktmpl_get_longpoll(tmpl);
	assert(lp->id);
	assert(!strcmp(lp->id, "myLPid"));
	assert(lp->uri);
	assert(!strcmp(lp->uri, "/LP"));
	assert(!blktmpl_get_submitold(tmpl));
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_bip23_bpe() {
	blktemplate_t *tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"expires\":99,\"target\":\"0000000077777777777777777777777777777777777777777777777777777777\"}", simple_time_rcvd));
	assert(tmpl->expires == 99);
	assert(!(*tmpl->target)[0]);
	for (int i = 1; i < 8; ++i) {
		assert((*tmpl->target)[i] == 0x77777777);
	}
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_bip23_mutations() {
	blktemplate_t *tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"maxtime\":2113929216,\"maxtimeoff\":50,\"mintime\":800,\"mintimeoff\":-50,\"mutable\":[\"prevblock\",\"version/force\"],\"noncerange\":\"01000000f0000000\"}", simple_time_rcvd));
	assert(tmpl->maxtime == 2113929216);
	assert(tmpl->maxtimeoff == 50);
	assert(tmpl->mintime == 800);
	assert(tmpl->mintimeoff == -50);
	// As of right now, implied mutations are not included in the value
	// assert(tmpl->mutations == (BMM_CBAPPEND | BMM_CBSET | BMM_GENERATE | BMM_TIMEINC | BMM_TIMEDEC | BMM_TXNADD | BMM_PREVBLK | BMM_VERFORCE));
	assert(caps_includes(tmpl->mutations, BMM_PREVBLK | BMM_VERFORCE));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"mutable\":[\"version/reduce\",\"coinbase/append\",\"generation\",\"time\",\"transactions\"],\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"transactions\":[]}", simple_time_rcvd));
	assert(tmpl->mutations == (BMM_CBAPPEND | BMM_GENERATE | BMM_TIMEINC | BMM_TIMEDEC | BMM_TXNADD | BMM_VERDROP));
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_bip23_abbrev() {
	blktemplate_t * const tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"mutable\":[\"submit/hash\",\"submit/coinbase\",\"submit/truncate\"]}", simple_time_rcvd));
	assert(tmpl->mutations == (BMA_TXNHASH | BMAb_COINBASE | BMAb_TRUNCATE));
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_bip9() {
	blktemplate_t *tmpl;
	
	tmpl = blktmpl_create();
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":536871040,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"rules\":[\"csv\"],\"vbavailable\":{\"!segwit\":7}}", simple_time_rcvd));
	assert(tmpl->version == 0x20000080);
	assert(tmpl->rules);
	assert(tmpl->rules[0]);
	assert(!strcmp(tmpl->rules[0], "csv"));
	assert(!tmpl->rules[1]);
	assert(!tmpl->unsupported_rule);
	assert(tmpl->vbavailable);
	assert(tmpl->vbavailable[0]);
	assert(tmpl->vbavailable[0]->name);
	assert(!strcmp(tmpl->vbavailable[0]->name, "!segwit"));
	assert(tmpl->vbavailable[0]->bitnum == 7);
	assert(!tmpl->vbavailable[1]);
	assert(!tmpl->vbrequired);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":536871040,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"rules\":[\"csv\"],\"vbavailable\":{\"!segwit\":7},\"vbrequired\":128}", simple_time_rcvd));
	assert(tmpl->version == 0x20000080);
	assert(tmpl->rules);
	assert(tmpl->rules[0]);
	assert(!strcmp(tmpl->rules[0], "csv"));
	assert(!tmpl->rules[1]);
	assert(!tmpl->unsupported_rule);
	assert(tmpl->vbavailable);
	assert(tmpl->vbavailable[0]);
	assert(tmpl->vbavailable[0]->name);
	assert(!strcmp(tmpl->vbavailable[0]->name, "!segwit"));
	assert(tmpl->vbavailable[0]->bitnum == 7);
	assert(!tmpl->vbavailable[1]);
	assert(tmpl->vbrequired == 0x80);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":536871040,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"rules\":[\"csv\",\"foo\"],\"vbavailable\":{}}", simple_time_rcvd));
	assert(tmpl->version == 0x20000080);
	assert(tmpl->rules);
	assert(tmpl->rules[0]);
	assert(!strcmp(tmpl->rules[0], "csv"));
	assert(tmpl->rules[1]);
	assert(!strcmp(tmpl->rules[1], "foo"));
	assert(!tmpl->rules[2]);
	assert(tmpl->unsupported_rule);
	assert(tmpl->vbavailable);
	assert(!tmpl->vbavailable[0]);
	assert(!tmpl->vbrequired);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":536871040,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"rules\":[\"csv\",\"!foo\"],\"vbavailable\":{}}", simple_time_rcvd));
	
	blktmpl_free(tmpl);
}

static void test_blktmpl_jansson_floaty() {
	blktemplate_t *tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":536871040.0,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.000,\"sigoplimit\":1000.0,\"sizelimit\":10000.0,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\"},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1.0],\"fee\":12.0,\"sigops\":4.0}],\"expires\":33.0,\"maxtime\":2113929216.0,\"maxtimeoff\":50.0,\"mintime\":800.0,\"mintimeoff\":-50.0,\"rules\":[\"csv\"],\"vbavailable\":{\"!segwit\":7.0},\"vbrequired\":128.0}", simple_time_rcvd));
	assert(tmpl->version == 536871040);
	assert(tmpl->height == 3);
	assert(!memcmp(tmpl->diffbits, "\xff\xff\0\x1d", 4));
	assert(tmpl->curtime == 777);
	for (int i = 0; i < 7; ++i) {
		assert(tmpl->prevblk[i] == 0x77777777);
	}
	assert(!tmpl->prevblk[7]);
	assert(tmpl->cbvalue == 512);
	
	assert(tmpl->txncount == 2);
	assert(tmpl->txns_datasz == 114);
	assert(tmpl->txns_sigops == -1);
	assert(tmpl->txns);
	assert(tmpl->txns[0].data);
	assert(tmpl->txns[0].datasz == 57);
	assert(!memcmp(tmpl->txns[0].data, "\x01\0\0\0\x01\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\xaa\xaa\xaa\xaa\0\x22\x22\x22\x22\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[0].dependscount == -1);
	assert(tmpl->txns[0].fee_ == -1);
	assert(tmpl->txns[0].sigops_ == -1);
	assert(tmpl->txns[1].data);
	assert(tmpl->txns[1].datasz == 57);
	assert(!memcmp(tmpl->txns[1].data, "\x01\0\0\0\x01\x1c\x69\xf2\x12\xe6\x2f\x2c\xdd\x80\x93\x7c\x9c\x08\x57\xce\xde\xc0\x05\xb1\x1d\x3b\x90\x2d\x21\0\x7c\x93\x2c\x1c\x7c\xd2\x0f\0\0\0\0\0\x44\x44\x44\x44\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[1].dependscount == 1);
	assert(tmpl->txns[1].depends);
	assert(tmpl->txns[1].depends[0] == 1);
	assert(tmpl->txns[1].fee_ == 12);
	assert(!tmpl->txns[1].required);
	assert(tmpl->txns[1].sigops_ == 4);
	assert(!memcmp(tmpl->txns[1].hash_, "\x8d\x7e\x01\x67\x43\x9d\xab\x18\x6e\x86\xf9\x13\xb2\x7f\x3a\xc2\x15\x67\xdd\x4e\xde\xf8\x9a\xa8\x01\x64\x99\x67\x8b\x1a\xda\x8e", 32));
	
	assert(tmpl->rules);
	assert(tmpl->rules[0]);
	assert(!strcmp(tmpl->rules[0], "csv"));
	assert(!tmpl->rules[1]);
	assert(!tmpl->unsupported_rule);
	assert(tmpl->vbavailable);
	assert(tmpl->vbavailable[0]);
	assert(tmpl->vbavailable[0]->name);
	assert(!strcmp(tmpl->vbavailable[0]->name, "!segwit"));
	assert(tmpl->vbavailable[0]->bitnum == 7);
	assert(!tmpl->vbavailable[1]);
	assert(tmpl->vbrequired == 0x80);
	
	assert(tmpl->sigoplimit == 1000);
	assert(tmpl->sizelimit == 10000);
	assert(tmpl->expires == 33);
	assert(tmpl->maxtime == 2113929216);
	assert(tmpl->maxtimeoff == 50);
	assert(tmpl->mintime == 800);
	assert(tmpl->mintimeoff == -50);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	// Truncate times (curtime perhaps ought to pull limits closer to it, but it's a fraction of a second anyway, so don't bother)
	// Ignore coinbasevalue problems if we have coinbasetxn
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":2.0,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.5,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.333,\"expires\":33.4,\"maxtime\":2113929216.6,\"maxtimeoff\":50.3,\"mintime\":800.4,\"mintimeoff\":-50.5,\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000000000\"}}", simple_time_rcvd));
	
	assert(tmpl->version == 2);
	assert(tmpl->height == 3);
	assert(!memcmp(tmpl->diffbits, "\xff\xff\0\x1d", 4));
	assert(tmpl->curtime == 777);
	for (int i = 0; i < 7; ++i) {
		assert(tmpl->prevblk[i] == 0x77777777);
	}
	assert(!tmpl->prevblk[7]);
	assert(!tmpl->cbvalue);
	
	assert(tmpl->expires == 33);
	assert(tmpl->maxtime == 2113929216);
	assert(tmpl->maxtimeoff == 50);
	assert(tmpl->mintime == 800);
	assert(tmpl->mintimeoff == -50);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	// Most values with a fraction should fail
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2.3,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.000}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2.0,\"height\":3.5,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.000}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":2.0,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.5}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":536871040.0,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.000,\"rules\":[\"csv\"],\"vbavailable\":{\"!segwit\":7.2},\"vbrequired\":128.0}", simple_time_rcvd));
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	assert(blktmpl_add_jansson_str(tmpl, "{\"version\":536871040.0,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.000,\"rules\":[\"csv\"],\"vbavailable\":{\"!segwit\":7.0},\"vbrequired\":128.6}", simple_time_rcvd));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	// Transaction-related values are optional, so it's safe to ignore them
	// Even though they could indicate varying rules, we have BIP9 to deal with that, and don't enforce the limits when missing tx info anyway
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3.0,\"height\":3.0,\"bits\":\"1d00ffff\",\"curtime\":777.0,\"previousblockhash\":\"0000000077777777777777777777777777777777777777777777777777777777\",\"coinbasevalue\":512.000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\"},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1.5],\"fee\":12.3,\"sigops\":4.6}],\"sigoplimit\":4444.4,\"sizelimit\":323333.3}", simple_time_rcvd));
	
	assert(tmpl->version == 3);
	assert(tmpl->height == 3);
	
	// These should be defaults
	assert(tmpl->sigoplimit >= 20000);
	assert(tmpl->sizelimit >= 1000000);
	
	assert(tmpl->txncount == 2);
	assert(tmpl->txns_datasz == 114);
	assert(tmpl->txns_sigops == -1);
	assert(tmpl->txns);
	assert(tmpl->txns[0].data);
	assert(tmpl->txns[0].datasz == 57);
	assert(!memcmp(tmpl->txns[0].data, "\x01\0\0\0\x01\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\xaa\xaa\xaa\xaa\0\x22\x22\x22\x22\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[0].dependscount == -1);
	assert(tmpl->txns[0].fee_ == -1);
	assert(tmpl->txns[0].sigops_ == -1);
	assert(tmpl->txns[1].data);
	assert(tmpl->txns[1].datasz == 57);
	assert(!memcmp(tmpl->txns[1].data, "\x01\0\0\0\x01\x1c\x69\xf2\x12\xe6\x2f\x2c\xdd\x80\x93\x7c\x9c\x08\x57\xce\xde\xc0\x05\xb1\x1d\x3b\x90\x2d\x21\0\x7c\x93\x2c\x1c\x7c\xd2\x0f\0\0\0\0\0\x44\x44\x44\x44\x01\0\x10\0\0\x01\x51\0\0\0\0", 57));
	assert(tmpl->txns[1].dependscount == -1);
	assert(tmpl->txns[1].fee_ == -1);
	assert(tmpl->txns[1].sigops_ == -1);
	assert(!memcmp(tmpl->txns[1].hash_, "\x8d\x7e\x01\x67\x43\x9d\xab\x18\x6e\x86\xf9\x13\xb2\x7f\x3a\xc2\x15\x67\xdd\x4e\xde\xf8\x9a\xa8\x01\x64\x99\x67\x8b\x1a\xda\x8e", 32));
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_submit_data_check(const char * const sa, const int level) {
	assert(strlen(sa) >= 160);
	assert(!memcmp(sa, "03000000777777a7777777a7777777a7777777a7777777a7777777a7777777a700000000", 72));
	// Don't check merkle root
	assert(!memcmp(&sa[136], "6d030000ff7f001d", 16));
	// Don't check nonce
	size_t pos = 160;
	if (level > 0) {
		assert(!strncmp(&sa[pos], "0401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000", 130));
		pos += 130;
		if (level > 1) {
			assert(!strcmp(&sa[pos], "01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa0022222222010010000001510000000001000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f000000000044444444010010000001510000000001000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000"));
			pos += strlen(&sa[pos]);
		}
	}
	if (level >= 0) {
		assert(sa[pos] == '\0');
	}
}

static void blktmpl_jansson_propose_check(json_t *j, const int level) {
	const char *sa;
	
	j = json_array_get(json_object_get(j, "params"), 0);
	assert((j = json_object_get(j, "data")));
	assert((sa = json_string_value(j)));
	return blktmpl_jansson_submit_data_check(sa, level);
}

static void blktmpl_jansson_propose() {
	blktemplate_t * const tmpl = blktmpl_create();
	const char *sa;
	json_t *j, *ja, *jb;
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbaseaux\":{\"dummy\":\"deadbeef\"},\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\"}", simple_time_rcvd));
	
	assert((j = blktmpl_propose_jansson(tmpl, 0, false)));
	check_request(j, blkmk_supported_rules, NULL);
	
	ja = json_array_get(json_object_get(j, "params"), 0);
	assert((jb = json_object_get(ja, "mode")));
	assert((sa = json_string_value(jb)));
	assert(!strcmp(sa, "proposal"));
	assert((jb = json_object_get(ja, "workid")));
	assert((sa = json_string_value(jb)));
	assert(!strcmp(sa, "mywork"));
	blktmpl_jansson_propose_check(j, 2);
	json_decref(j);
	
	tmpl->mutations |= BMAb_COINBASE;
	assert((j = blktmpl_propose_jansson(tmpl, 0, false)));
	check_request(j, blkmk_supported_rules, NULL);
	blktmpl_jansson_propose_check(j, 1);
	json_decref(j);
	
	tmpl->mutations |= BMAb_TRUNCATE;
	assert((j = blktmpl_propose_jansson(tmpl, 0, false)));
	check_request(j, blkmk_supported_rules, NULL);
	blktmpl_jansson_propose_check(j, 0);
	json_decref(j);
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_submit() {
	blktemplate_t * const tmpl = blktmpl_create();
	const char *sa;
	uint8_t data[76];
	int16_t i16;
	unsigned int dataid;
	json_t *j, *ja, *jb, *jc;
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbaseaux\":{\"dummy\":\"deadbeef\"},\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\",\"mutable\":[\"submit/coinbase\",\"submit/truncate\",\"coinbase/append\"]}", simple_time_rcvd));
	
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &dataid));
	
	assert((j = blkmk_submit_foreign_jansson(tmpl, data, 0, 0x12345678)));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 1);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, 2);
	if (json_array_size(ja) >= 2) {
		assert(json_is_object((jb = json_array_get(ja, 1))));
		assert(!json_object_get(jb, "workid"));
	}
	json_decref(j);
	
	assert((j = blkmk_submit_jansson(tmpl, data, 0, 0x12345678)));
	assert(json_object_get(j, "id"));
	assert((ja = json_object_get(j, "method")));
	assert((sa = json_string_value(ja)));
	assert(!strcmp(sa, "submitblock"));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 2);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, 0);
	assert(!memcmp(&sa[72], "512a63f45f96f0269a2d23ccd96bcf0322ee4f60254748e30b89e2b59431aba16d030000ff7f001d12345678", 64));  // merkle root
	assert(!memcmp(&sa[152], "12345678", 8));  // nonce
	assert(json_is_object((jb = json_array_get(ja, 1))));
	assert((jc = json_object_get(jb, "workid")));
	assert((sa = json_string_value(jc)));
	assert(!strcmp(sa, "mywork"));
	json_decref(j);
	
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &dataid));
	
	assert((j = blkmk_submit_jansson(tmpl, data, dataid, 0x12345678)));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 2);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, -1);
	// TODO: Check inserted dataid
	assert(json_is_object((jb = json_array_get(ja, 1))));
	assert((jc = json_object_get(jb, "workid")));
	assert((sa = json_string_value(jc)));
	assert(!strcmp(sa, "mywork"));
	json_decref(j);
	
	blktmpl_free(tmpl);
}

static void blktmpl_jansson_submitm() {
	blktemplate_t * const tmpl = blktmpl_create();
	const char *sa;
	uint8_t data[76], *cbtxn, *branches, extranonce[10];
	size_t cbextranonceoffset, cbtxnsize;
	int branchcount;
	int16_t i16;
	json_t *j, *ja, *jb, *jc;
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbaseaux\":{\"dummy\":\"deadbeef\"},\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\",\"mutable\":[\"submit/coinbase\",\"submit/truncate\",\"coinbase/append\"]}", simple_time_rcvd));
	
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, 1, false));
	free(cbtxn);
	free(branches);
	memset(&data[36], '\xee', 32);  // merkle root, must be provided by caller
	
	extranonce[0] = 11;
	assert((j = blkmk_submitm_jansson(tmpl, data, extranonce, 1, 0x12345678, false)));
	assert(json_object_get(j, "id"));
	assert((ja = json_object_get(j, "method")));
	assert((sa = json_string_value(ja)));
	assert(!strcmp(sa, "submitblock"));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 2);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, -1);
	assert(!strcmp(&sa[160], "0401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08010404deadbeef0b333333330100100000015100000000"));
	assert(json_is_object((jb = json_array_get(ja, 1))));
	assert((jc = json_object_get(jb, "workid")));
	assert((sa = json_string_value(jc)));
	assert(!strcmp(sa, "mywork"));
	json_decref(j);
	
	extranonce[0] = 22;
	assert((j = blkmk_submitm_jansson(tmpl, data, extranonce, 1, 0x12345678, true)));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 2);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, -1);
	assert(!strcmp(&sa[160], "0401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08010404deadbeef1633333333010010000001510000000001000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa0022222222010010000001510000000001000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f000000000044444444010010000001510000000001000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000"));
	json_decref(j);
	
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, 3, false));
	free(cbtxn);
	free(branches);
	
	extranonce[0] = 0x11;
	extranonce[1] = 0x22;
	extranonce[2] = 0x33;
	assert((j = blkmk_submitm_jansson(tmpl, data, extranonce, 3, 0x12345678, false)));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 2);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, -1);
	assert(!strcmp(&sa[160], "0401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0a010404deadbeef112233333333330100100000015100000000"));
	json_decref(j);
	
	extranonce[2] = 0xed;
	assert((j = blkmk_submitm_jansson(tmpl, data, extranonce, 3, 0x12345678, true)));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 2);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, -1);
	assert(!strcmp(&sa[160], "0401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0a010404deadbeef1122ed33333333010010000001510000000001000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa0022222222010010000001510000000001000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f000000000044444444010010000001510000000001000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000"));
	json_decref(j);
	
	blktmpl_free(tmpl);
}

static void test_blkmk_varint_encode_internal(const unsigned long txncount, const char * const expected, const size_t expectedsz) {
	blktemplate_t * const tmpl = blktmpl_create();
	const char *sa;
	uint8_t data[76];
	int16_t i16;
	unsigned int dataid;
	json_t *j, *ja, *jb;
	
	j = json_loads("{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"transactions\":[{\"data\":\"01\"}],\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"mutable\":[\"submit/coinbase\"]}", 0, NULL);
	assert(j);
	assert((ja = json_object_get(j, "transactions")));
	assert((jb = json_array_get(ja, 0)));
	for (unsigned int i = 2; i < txncount; ++i) {
		assert(!json_array_append(ja, jb));
	}
	assert(json_array_size(ja) == txncount - 1);
	assert(!blktmpl_add_jansson(tmpl, j, simple_time_rcvd));
	json_decref(j);
	
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &dataid));
	
	assert((j = blkmk_submit_jansson(tmpl, data, 0, 0x12345678)));
	assert((ja = json_object_get(j, "params")));
	assert(json_is_array(ja));
	assert(json_array_size(ja) >= 1);
	assert((sa = json_string_value(json_array_get(ja, 0))));
	blktmpl_jansson_submit_data_check(sa, -1);
	assert(!memcmp(&sa[160], expected, expectedsz));  // tx count + gentx version
	json_decref(j);
	
	blktmpl_free(tmpl);
}

static void test_blkmk_varint_encode() {
	test_blkmk_varint_encode_internal(4, "0401000000", 10);
	test_blkmk_varint_encode_internal(0xfc, "fc01000000", 10);
	test_blkmk_varint_encode_internal(0xfd, "fdfd0001000000", 14);
	test_blkmk_varint_encode_internal(0xffff, "fdffff01000000", 14);
	test_blkmk_varint_encode_internal(0x10000, "fe0000010001000000", 18);
	// TODO: Find a way to test 64-bit and upper 32-bit
}

static void test_blkmk_supports_rule() {
	for (const char **rule = blkmk_supported_rules; *rule; ++rule) {
		assert(blkmk_supports_rule(*rule));
		char important_rule[strlen(*rule) + 2];
		important_rule[0] = '!';
		strcpy(&important_rule[1], *rule);
		assert(!blkmk_supports_rule(important_rule));
	}
	assert(!blkmk_supports_rule("foo"));
	assert(!blkmk_supports_rule(""));
}

static void test_blkmk_address_to_script() {
	uint8_t script[0x100];
	
	assert(blkmk_address_to_script(script, sizeof(script), "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Wh") == 25);
	assert(!memcmp(script, "\x76\xa9\x14\xfe\x14\xc4\xc6\x8d\x83\xda\x61\xfc\x57\x7b\x04\xcb\x6e\xcb\x6d\x31\xba\x1d\x52\x88\xac", 25));
	
	assert(blkmk_address_to_script(script, sizeof(script), "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == 23);
	assert(!memcmp(script, "\xa9\x14\xb4\x72\xa2\x66\xd0\xbd\x89\xc1\x37\x06\xa4\x13\x2c\xcf\xb1\x6f\x7c\x3b\x9f\xcb\x87", 23));
	
	assert(blkmk_address_to_script(script, sizeof(script), "1BitcoinEaterAddressDontSendf59kuE") == 25);
	assert(!memcmp(script, "\x76\xa9\x14\x75\x9d\x66\x77\x09\x1e\x97\x3b\x9e\x9d\x99\xf1\x9c\x68\xfb\xf4\x3e\x3f\x05\xf9\x88\xac", 25));
	
	assert(blkmk_address_to_script(script, 25, "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Wh") == 25);
	assert(!memcmp(script, "\x76\xa9\x14\xfe\x14\xc4\xc6\x8d\x83\xda\x61\xfc\x57\x7b\x04\xcb\x6e\xcb\x6d\x31\xba\x1d\x52\x88\xac", 25));
	
	assert(blkmk_address_to_script(script, 23, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == 23);
	assert(!memcmp(script, "\xa9\x14\xb4\x72\xa2\x66\xd0\xbd\x89\xc1\x37\x06\xa4\x13\x2c\xcf\xb1\x6f\x7c\x3b\x9f\xcb\x87", 23));
	
	assert(blkmk_address_to_script(script, 25, "1BitcoinEaterAddressDontSendf59kuE") == 25);
	assert(!memcmp(script, "\x76\xa9\x14\x75\x9d\x66\x77\x09\x1e\x97\x3b\x9e\x9d\x99\xf1\x9c\x68\xfb\xf4\x3e\x3f\x05\xf9\x88\xac", 25));
	
	// Missing last letter
	assert(!blkmk_address_to_script(script, sizeof(script), "1QATWksNFGeUJCWBrN4g6hGM178Lovm7W"));
	// Extra letters/symbols
	assert(!blkmk_address_to_script(script, sizeof(script), "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Whz"));
	assert(!blkmk_address_to_script(script, sizeof(script), "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Wh\xff"));
	assert(!blkmk_address_to_script(script, sizeof(script), "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Wh\x01"));
	assert(!blkmk_address_to_script(script, sizeof(script), "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Wh/"));
	// Missing last byte (decoded)
	assert(!blkmk_address_to_script(script, sizeof(script), "16FNsF1zNp3bjQuNwgfSdBUwq4CdfGoh"));
	// Extra byte (decoded)
	assert(!blkmk_address_to_script(script, sizeof(script), "12mEk2LdJmz4PUumptsyDa8ijHU3QS8Hhh1"));
	assert(!blkmk_address_to_script(script, sizeof(script), ""));
	assert(!blkmk_address_to_script(script, sizeof(script), "\x01"));
	assert(!blkmk_address_to_script(script, sizeof(script), "\xff"));
	
	// Too little buffer space
	assert(blkmk_address_to_script(script, 20, "1QATWksNFGeUJCWBrN4g6hGM178Lovm7Wh") == 25);
	assert(blkmk_address_to_script(script, 0, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == 23);
	assert(blkmk_address_to_script(script, 24, "1BitcoinEaterAddressDontSendf59kuE") == 25);
}

static void test_blkmk_x_left() {
	blktemplate_t *tmpl = blktmpl_create();
	uint8_t data[76];
	int16_t i16;
	unsigned int dataid, orig_work_left;
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"transactions\":[],\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"expires\":44}", simple_time_rcvd));
	
	assert(blkmk_work_left(tmpl) == 1);
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &dataid));
	assert(blkmk_work_left(tmpl) == 0);
	
	assert(blkmk_time_left(tmpl, simple_time_rcvd) == 44);
	assert(blkmk_time_left(tmpl, simple_time_rcvd + 1) == 43);
	assert(blkmk_time_left(tmpl, simple_time_rcvd + 43) == 1);
	assert(blkmk_time_left(tmpl, simple_time_rcvd + 50) == 0);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"transactions\":[],\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"mutable\":[\"coinbase/append\"]}", simple_time_rcvd));
	
	orig_work_left = blkmk_work_left(tmpl);
	assert(orig_work_left > 0xf0);
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &dataid));
	assert(blkmk_work_left(tmpl) == orig_work_left - 1);
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &dataid));
	assert(blkmk_work_left(tmpl) == orig_work_left - 2);
	
	blktmpl_free(tmpl);
}

static void test_blkmk_get_data() {
	blktemplate_t *tmpl = blktmpl_create();
	uint8_t data[76];
	int16_t i16;
	unsigned int dataid, first_dataid;
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbaseaux\":{\"dummy\":\"deadbeef\"},\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\",\"mutable\":[\"submit/coinbase\",\"submit/truncate\",\"coinbase/append\"],\"expires\":32}", simple_time_rcvd));
	
	assert(blkmk_work_left(tmpl) > 0xf0);
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &first_dataid));
	assert(first_dataid == 0);
	assert(i16 == 31 || i16 == 32);
	assert(!memcmp(data, "\x03\0\0\0\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\0\0\0\0\x51\x2a\x63\xf4\x5f\x96\xf0\x26\x9a\x2d\x23\xcc\xd9\x6b\xcf\x03\x22\xee\x4f\x60\x25\x47\x48\xe3\x0b\x89\xe2\xb5\x94\x31\xab\xa1\x6d\x03\0\0\xff\x7f\0\x1d", 76));
	
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd + 4, &i16, &dataid));
	assert(dataid == first_dataid + 1);
	assert(i16 == 27 || i16 == 28);
	assert(!memcmp(data, "\x03\0\0\0\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\0\0\0\0\x2a\x73\x99\xbc\x0a\x19\xa1\x11\x03\xfc\x3b\x8f\x4b\xe4\0\x68\x18\xea\x3f\x2a\0\xcf\x42\x8b\xd7\x09\x1c\x8d\xe2\xea\xe7\x38\x71\x03\0\0\xff\x7f\0\x1d", 76));
	
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data) + 1, simple_time_rcvd + 8, &i16, &dataid));
	assert(dataid == first_dataid + 2);
	assert(i16 == 23 || i16 == 24);
	assert(!memcmp(data, "\x03\0\0\0\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\0\0\0\0\xe2\xe4\xbc\x8e\x65\x8b\x52\x2e\xe5\xeb\x69\xd5\xe5\xd4\xa6\x25\xfd\x8f\x32\x2d\x71\x0f\xc0\xb2\x38\xe1\x71\x01\x61\x56\x2c\x2e\x75\x03\0\0\xff\x7f\0\x1d", 76));
	
	// Too-small buffer fails with desired buffer size
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data) - 1, simple_time_rcvd + 8, &i16, &dataid));
	// Make sure dataid wasn't incremented for the failure
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd + 8, &i16, &dataid));
	assert(dataid == first_dataid + 3);
	
	// Bad hash function should fail
	blkmk_sha256_impl = bad_sha256;
	assert(0 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd + 8, &i16, &dataid));
	blkmk_sha256_impl = my_sha256;
	
	// No more time, fail
	assert(0 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd + 35, &i16, &dataid));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbaseaux\":{\"dummy\":\"deadbeef\"},\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\",\"expires\":32}", simple_time_rcvd));
	// Make sure a non-appendable fails the second get_data
	assert(76 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &first_dataid));
	assert(first_dataid == 0);
	assert(0 == blkmk_get_data(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &first_dataid));
	
	// TODO: ensure a scriptsig with <4 bytes cannot be produced through to get_data; but this requires a platform where sizeof(unsigned int) < 4 and no height-in-coinbase...
	
	blktmpl_free(tmpl);
}

static void test_blkmk_get_mdata() {
	blktemplate_t *tmpl = blktmpl_create();
	uint8_t data[76], *cbtxn, *branches;
	size_t cbextranonceoffset, cbtxnsize;
	int branchcount;
	int16_t i16;
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000\"},\"workid\":\"mywork\",\"mutable\":[\"submit/coinbase\",\"submit/truncate\",\"coinbase/append\"],\"expires\":99}", simple_time_rcvd));
	
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, 1, false));
	assert(!memcmp(data, "\x03\0\0\0\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\0\0\0\0", 36));
	// Skip merkle root
	assert(!memcmp(&data[68], "\x6d\x03\0\0\xff\x7f\0\x1d", 8));
	assert(i16 == 98 || i16 == 99);
	assert(cbtxnsize == 65);
	assert(cbextranonceoffset == 49);
	assert(!memcmp(cbtxn, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x08\x01\x04\x04\xde\xad\xbe\xef", 49));
	assert(!memcmp(&cbtxn[50], "\x33\x33\x33\x33\x01\0\x10\0\0\x01\x51\0\0\0\0", 65-50));
	assert(branchcount == 2);
	assert(!memcmp(branches, "\x0f\xd2\x7c\x1c\x2c\x93\x7c\0\x21\x2d\x90\x3b\x1d\xb1\x05\xc0\xde\xce\x57\x08\x9c\x7c\x93\x80\xdd\x2c\x2f\xe6\x12\xf2\x69\x1c\x2b\x07\x3c\xb8\x85\xbf\x62\x3b\x1c\xd5\xac\xda\x81\xce\xe8\x9f\xe9\x19\x0e\x10\x85\xff\x54\x98\xc3\x33\x4c\x2c\x63\xf8\xdd\x4d", 64));
	free(cbtxn);
	free(branches);
	
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd + 4, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, 3, false));
	assert(!memcmp(data, "\x03\0\0\0\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\0\0\0\0", 36));
	// Skip merkle root
	assert(!memcmp(&data[68], "\x71\x03\0\0\xff\x7f\0\x1d", 8));
	assert(i16 == 94 || i16 == 95);
	assert(cbtxnsize == 67);
	assert(cbextranonceoffset == 49);
	assert(!memcmp(cbtxn, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x0a\x01\x04\x04\xde\xad\xbe\xef", 49));
	assert(!memcmp(&cbtxn[52], "\x33\x33\x33\x33\x01\0\x10\0\0\x01\x51\0\0\0\0", 67-52));
	assert(branchcount == 2);
	assert(!memcmp(branches, "\x0f\xd2\x7c\x1c\x2c\x93\x7c\0\x21\x2d\x90\x3b\x1d\xb1\x05\xc0\xde\xce\x57\x08\x9c\x7c\x93\x80\xdd\x2c\x2f\xe6\x12\xf2\x69\x1c\x2b\x07\x3c\xb8\x85\xbf\x62\x3b\x1c\xd5\xac\xda\x81\xce\xe8\x9f\xe9\x19\x0e\x10\x85\xff\x54\x98\xc3\x33\x4c\x2c\x63\xf8\xdd\x4d", 64));
	free(cbtxn);
	free(branches);
	
	size_t sizeof_dataid = sizeof(unsigned int);
	size_t expected_space = sizeof_dataid + 1;
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd + 8, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, sizeof_dataid, false));
	assert(!memcmp(data, "\x03\0\0\0\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\x77\x77\x77\xa7\0\0\0\0", 36));
	// Skip merkle root
	assert(!memcmp(&data[68], "\x75\x03\0\0\xff\x7f\0\x1d", 8));
	assert(i16 == 90 || i16 == 91);
	assert(cbtxnsize == 64 + expected_space);
	assert(cbextranonceoffset == 49);
	assert(!memcmp(cbtxn, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff", 41));
	assert(cbtxn[41] == 7 + expected_space);
	assert(!memcmp(&cbtxn[42], "\x01\x04\x04\xde\xad\xbe\xef", 7));
	assert(!memcmp(&cbtxn[49 + expected_space], "\x33\x33\x33\x33\x01\0\x10\0\0\x01\x51\0\0\0\0", 15));
	assert(branchcount == 2);
	assert(!memcmp(branches, "\x0f\xd2\x7c\x1c\x2c\x93\x7c\0\x21\x2d\x90\x3b\x1d\xb1\x05\xc0\xde\xce\x57\x08\x9c\x7c\x93\x80\xdd\x2c\x2f\xe6\x12\xf2\x69\x1c\x2b\x07\x3c\xb8\x85\xbf\x62\x3b\x1c\xd5\xac\xda\x81\xce\xe8\x9f\xe9\x19\x0e\x10\x85\xff\x54\x98\xc3\x33\x4c\x2c\x63\xf8\xdd\x4d", 64));
	free(cbtxn);
	free(branches);
	
	// If hashing fails, so must get_mdata
	blkmk_sha256_impl = bad_sha256;
	assert(!blkmk_get_mdata(tmpl, data, sizeof(data) - 1, simple_time_rcvd + 8, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, sizeof_dataid, false));
	blkmk_sha256_impl = my_sha256;
	
	// Buffer too small must fail
	assert(!blkmk_get_mdata(tmpl, data, sizeof(data) - 1, simple_time_rcvd + 8, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, sizeof_dataid, false));
	
	// Without cb append/set mutations, we must fail too
	tmpl->mutations &= ~(BMM_CBAPPEND | BMM_CBSET);
	assert(!blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd + 8, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, sizeof_dataid, false));
	// ... but only one or the other should be sufficient
	tmpl->mutations |= BMM_CBAPPEND;
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd + 8, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, sizeof_dataid, false));
	free(cbtxn);
	free(branches);
	tmpl->mutations = (tmpl->mutations & ~BMM_CBAPPEND) | BMM_CBSET;
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd + 8, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, sizeof_dataid, false));
	free(cbtxn);
	free(branches);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":100,\"sizelimit\":1000,\"transactions\":[{\"data\":\"01000000019999999999999999999999999999999999999999999999999999999999999999aaaaaaaa00222222220100100000015100000000\",\"required\":true},{\"hash\":\"8eda1a8b67996401a89af8de4edd6715c23a7fb213f9866e18ab9d4367017e8d\",\"data\":\"01000000011c69f212e62f2cdd80937c9c0857cedec005b11d3b902d21007c932c1c7cd20f0000000000444444440100100000015100000000\",\"depends\":[1],\"fee\":12,\"required\":false,\"sigops\":4},{\"data\":\"01000000010099999999999999999999999999999999999999999999999999999999999999aaaaaaaa00555555550100100000015100000000\"}],\"mutable\":[\"coinbase/append\"]}", simple_time_rcvd));
	
	// No generation transaction, fail
	assert(!blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, 1, false));
	
	// Initialising it should make us work though
	assert(blkmk_init_generation(tmpl, NULL, 0) == 640);
	assert(blkmk_get_mdata(tmpl, data, sizeof(data), simple_time_rcvd, &i16, &cbtxn, &cbtxnsize, &cbextranonceoffset, &branchcount, &branches, 1, false));
	assert(cbtxn[41] >= 4 /* libblkmaker_coinbase_size_minimum */);
	free(cbtxn);
	free(branches);
	
	blktmpl_free(tmpl);
}

static const void *my_memmemr(const void * const haystack_p, const size_t haystacklen, const void * const needle, const size_t needlelen) {
	if (needlelen > haystacklen)
		return NULL;
	const uint8_t * const haystack = haystack_p, *p;
	for (ssize_t i = haystacklen - needlelen; i >= 0; --i) {
		p = &haystack[i];
		if (!memcmp(p, needle, needlelen)) {
			return p;
		}
	}
	return NULL;
}

static void test_blkmk_init_generation() {
	blktemplate_t *tmpl;
	bool newcb;
	
	tmpl = blktmpl_create();
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640}", simple_time_rcvd));
	assert(!tmpl->cbtxn);
	assert(blkmk_init_generation(tmpl, NULL, 0) == 640);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 62);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x02\x01\x04\xff\xff\xff\xff\x01\x80\x02\0\0\0\0\0\0\0\0\0\0\0", tmpl->cbtxn->datasz));
	
	newcb = false;
	assert(!blkmk_init_generation3(tmpl, "\0", 1, &newcb));
	
	newcb = true;
	assert(blkmk_init_generation3(tmpl, "\x04" "test", 5, &newcb));
	assert(newcb);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 67);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x02\x01\x04\xff\xff\xff\xff\x01\x80\x02\0\0\0\0\0\0\x05\x04" "test\0\0\0\0", tmpl->cbtxn->datasz));
	
	assert(!blkmk_init_generation2(tmpl, "\0", 1, &newcb));
	assert(!newcb);
	
	tmpl->mutations &= ~BMM_GENERATE;
	newcb = true;
	assert(!blkmk_init_generation3(tmpl, "\0", 1, &newcb));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":40000000,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"coinbaseaux\":{\"dummy\":\"aabbccddeeff0011\"}}", simple_time_rcvd));
	assert(blkmk_init_generation(tmpl, NULL, 0) == 640);
	assert(my_memmemr(&tmpl->cbtxn->data[42], tmpl->cbtxn->data[41], "\xaa\xbb\xcc\xdd\xee\xff\0\x11", 8));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":128,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"coinbaseaux\":{\"dummy\":\"aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff001199\"}}", simple_time_rcvd));
	assert(!blkmk_init_generation(tmpl, NULL, 0));
	tmpl->height = 4;
	assert(blkmk_init_generation(tmpl, NULL, 0) == 640);
	tmpl->cbvalue = 0;
	newcb = true;
	// Unknown cbvalue needs to either fail, or figure it out from an existing cbtxn (which we don't support yet)
	assert(!blkmk_init_generation3(tmpl, NULL, 0, &newcb));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":40000000,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":10000000000}", simple_time_rcvd));
	newcb = false;
	assert(blkmk_init_generation3(tmpl, "\x04" "test", 5, &newcb));
	assert(newcb);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 70);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x05\x04\0\x5a\x62\x02\xff\xff\xff\xff\x01\0\xe4\x0b\x54\x02\0\0\0\x05\x04" "test\0\0\0\0", tmpl->cbtxn->datasz));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":40000000,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000000000\"},\"mutable\":[\"generation\"],\"coinbasevalue\":89064736821248}", simple_time_rcvd));
	newcb = false;
	assert(!blkmk_init_generation3(tmpl, "\x04" "test", 5, &newcb));
	assert(!newcb);
	newcb = true;
	assert(blkmk_init_generation3(tmpl, "\x04" "test", 5, &newcb));
	assert(newcb);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 70);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x05\x04\0\x5a\x62\x02\xff\xff\xff\xff\x01\0\x10\0\0\x01\x51\0\0\x05\x04" "test\0\0\0\0", tmpl->cbtxn->datasz));
	
	tmpl->sizelimit = 151;
	assert(blkmk_init_generation3(tmpl, "\x04" "test", 5, &newcb));
	assert(!blkmk_init_generation3(tmpl, "\x05" "testx", 6, &newcb));
	tmpl->sizelimit = 10000;
	tmpl->sigoplimit = 1;
	assert(blkmk_init_generation3(tmpl, "\x05" "testx", 6, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac", 7, &newcb));
	assert(!blkmk_init_generation3(tmpl, "\x05" "testx\xac\xac", 8, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\x4c\0", 9, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\x4c", 8, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\x4d\x01", 9, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\x4e\x01", 9, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\x4e\0\0\0\0", 12, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x4c\x04" "estx\xad", 7, &newcb));
	assert(!blkmk_init_generation3(tmpl, "\x4c\x04" "estx\xad\xad", 8, &newcb));
	assert(!blkmk_init_generation3(tmpl, "\x4c\x04" "estx\xac\xad", 8, &newcb));
	tmpl->sigoplimit = 21;
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\xac", 8, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x05" "testx\xac\xae", 8, &newcb));
	assert(!blkmk_init_generation3(tmpl, "\x05" "testx\xac\xae\xac", 9, &newcb));
	assert(blkmk_init_generation3(tmpl, "\x4d\x03\0" "stx\xac\xaf", 8, &newcb));
	assert(!blkmk_init_generation3(tmpl, "\x4d\x03\0" "stx\xac\xaf\xac", 9, &newcb));
	
	blktmpl_free(tmpl);
}

static void test_blkmk_append_coinbase_safe() {
	blktemplate_t *tmpl;
	bool newcb;
	static const uint8_t lots_of_zero[100] = {0};
	
	tmpl = blktmpl_create();
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000000000\"}}", simple_time_rcvd));
	// Should fail because we lack coinbase/append mutability
	assert(blkmk_append_coinbase_safe(tmpl, "", 1) <= 0);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef333333330100100000015100000000000000\"},\"mutable\":[\"coinbase/append\"]}", simple_time_rcvd));
	assert(blkmk_append_coinbase_safe(tmpl, "", 1) >= 1);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 68);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x08\x01\x04\x04\xde\xad\xbe\xef\0\x33\x33\x33\x33\x01\0\x10\0\0\x01\x51\0\0\0\0\0\0\0", tmpl->cbtxn->datasz));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasevalue\":640,\"sigoplimit\":21}", simple_time_rcvd));
	assert(blkmk_init_generation(tmpl, NULL, 0) == 640);
	assert(blkmk_append_coinbase_safe(tmpl, "", 1) >= 1);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 63);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x03\x01\x04\0\xff\xff\xff\xff\x01\x80\x02\0\0\0\0\0\0\0\0\0\0\0", tmpl->cbtxn->datasz));
	
	// With 99-byte extranonce, we're already beyond the limit
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 99, true) <= 0);
	// This should just barely break the limit
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 100 - tmpl->cbtxn->data[41], true) == 0);
	// This should be okay
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 100 - tmpl->cbtxn->data[41] - 1, true) == 1);
	// Up to 21 sigops is okay
	assert(blkmk_append_coinbase_safe2(tmpl, "\xae", 1, 3, true) >= 1);
	assert(blkmk_append_coinbase_safe2(tmpl, "\xac", 1, 3, true) >= 1);
	// But 22 should hit the limit
	assert(blkmk_append_coinbase_safe2(tmpl, "\xac", 1, 3, true) < 0);
	// Non-sigop stuff is fine to continue
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 3, true) >= 1);
	const uint8_t padsz = 100 - tmpl->cbtxn->data[41] - 3;
	assert(blkmk_append_coinbase_safe2(tmpl, lots_of_zero, padsz, 3, true) == padsz);
	// One too many
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 3, true) == 0);
	// Becomes okay if we reduce extranonce size
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 2, true) == 1);
	assert(blkmk_append_coinbase_safe2(tmpl, lots_of_zero, 2, 0, true) == 2);
	// Totally full now
	assert(blkmk_append_coinbase_safe2(tmpl, "", 1, 0, true) == 0);
	
	newcb = true;
	assert(blkmk_init_generation3(tmpl, NULL, 0, &newcb));
	tmpl->sizelimit = tmpl->cbtxn->datasz + 81 + 5;
	assert(blkmk_append_coinbase_safe2(tmpl, "\x04" "test", 5, 0, true) == 5);
	assert(blkmk_init_generation3(tmpl, NULL, 0, &newcb));
	assert(blkmk_append_coinbase_safe2(tmpl, "\x05" "testx", 6, 0, true) == 5);
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	// Gen tx is cut off immediately after the coinbase.
	// We don't *really* care that this works since it's not Bitcoin, but we need to make sure it doesn't corrupt memory or crash
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbeef\"},\"mutable\":[\"coinbase/append\"]}", simple_time_rcvd));
	assert(blkmk_append_coinbase_safe(tmpl, "\x58", 1) >= 1);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 50);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x08\x01\x04\x04\xde\xad\xbe\xef\x58", tmpl->cbtxn->datasz));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	// Gen tx is cut off INSIDE the coinbase.
	// Again, we need to make sure it doesn't corrupt memory or crash
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07010404deadbe\"},\"mutable\":[\"coinbase/append\"]}", simple_time_rcvd));
	assert(blkmk_append_coinbase_safe(tmpl, "\x58", 1) <= 0);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 48);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\x07\x01\x04\x04\xde\xad\xbe", tmpl->cbtxn->datasz));
	
	blktmpl_free(tmpl);
	tmpl = blktmpl_create();
	
	// Gen tx is cut off BEFORE the coinbase
	assert(!blktmpl_add_jansson_str(tmpl, "{\"version\":3,\"height\":4,\"bits\":\"1d007fff\",\"curtime\":877,\"previousblockhash\":\"00000000a7777777a7777777a7777777a7777777a7777777a7777777a7777777\",\"coinbasetxn\":{\"data\":\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff\"},\"mutable\":[\"coinbase/append\"]}", simple_time_rcvd));
	assert(blkmk_append_coinbase_safe(tmpl, "\x58", 1) <= 0);
	assert(tmpl->cbtxn);
	assert(tmpl->cbtxn->datasz == 41);
	assert(!memcmp(tmpl->cbtxn->data, "\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff", tmpl->cbtxn->datasz));
	
	blktmpl_free(tmpl);
}

int main() {
	blkmk_sha256_impl = my_sha256;
	
	puts("capabilityname");
	capabilityname_test();
	
	puts("blktxn");
	blktxn_test('\0');
	blktxn_test('\xa5');
	blktxn_test('\xff');
	
	puts("blktmpl");
	blktmpl_test();
	
	puts("blktmpl_request_jansson");
	blktmpl_request_jansson_test_old();
	blktmpl_request_jansson_test_custom_rulelist();
	blktmpl_request_jansson_test_custom_caps();
	blktmpl_request_jansson_test_longpoll();
	
	puts("blktmpl_jansson");
	blktmpl_jansson_simple();
	blktmpl_jansson_bip22_required();
	blktmpl_jansson_bip22_longpoll();
	blktmpl_jansson_bip23_bpe();
	blktmpl_jansson_bip23_mutations();
	blktmpl_jansson_bip23_abbrev();
	blktmpl_jansson_bip9();
	test_blktmpl_jansson_floaty();
	blktmpl_jansson_propose();
	blktmpl_jansson_submit();
	blktmpl_jansson_submitm();
	
	puts("blkmk_varint_encode");
	test_blkmk_varint_encode();
	
	puts("blkmk_supports_rule");
	test_blkmk_supports_rule();
	
	puts("blkmk_address_to_script");
	test_blkmk_address_to_script();
	
	puts("blkmk_*_left");
	test_blkmk_x_left();
	
	puts("blkmk_get_data");
	test_blkmk_get_data();
	
	puts("blkmk_get_mdata");
	test_blkmk_get_mdata();
	
	puts("blkmk_init_generation");
	test_blkmk_init_generation();
	
	puts("blkmk_append_coinbase_safe");
	test_blkmk_append_coinbase_safe();
}

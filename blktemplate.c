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
#include <strings.h>

#include <blktemplate.h>

static const char *capnames[] = {
	"coinbasetxn",
	"coinbasevalue",
	"workid",
	
	"longpoll",
	"proposal",
	"serverlist",
	                                     NULL, NULL,
	NULL, NULL, NULL, NULL,  NULL, NULL, NULL, NULL,
	
	"coinbase/append",
	"coinbase",
	"generation",
	"time/increment",
	"time/decrement",
	"transactions/add",
	"prevblock",
	"version/force",
	"version/reduce",
	
	"submit/hash",
	"submit/coinbase",
	"submit/truncate",
	"share/coinbase",
	"share/merkle",
	"share/truncate",
};

const char *blktmpl_capabilityname(gbt_capabilities_t caps) {
	for (unsigned int i = 0; i < GBT_CAPABILITY_COUNT; ++i)
		if (caps & (1 << i))
			return capnames[i];
	return NULL;
}

uint32_t blktmpl_getcapability(const char *n) {
	for (unsigned int i = 0; i < GBT_CAPABILITY_COUNT; ++i)
		if (capnames[i] && !strcasecmp(n, capnames[i]))
			return ((uint32_t)1) << i;
	if (!strcasecmp(n, "time")) {
		// multi-capability
		return BMM_TIMEINC | BMM_TIMEDEC;
	}
	if (!strcasecmp(n, "transactions"))
		return BMM_TXNADD;  // Odd one as it's overloaded w/"transactions/add" per spec
	return 0;
}

void blktxn_init(struct blktxn_t * const txn) {
	txn->data = NULL;
	txn->datasz = 0;
	txn->hash = NULL;
	txn->hash_ = NULL;
	txn->txid = NULL;
	
	txn->dependscount = -1;
	txn->depends = NULL;
	
	txn->fee_ = -1;
	txn->required = false;
	txn->sigops_ = -1;
	txn->weight = -1;
}

blktemplate_t *blktmpl_create() {
	blktemplate_t *tmpl;
	tmpl = calloc(1, sizeof(*tmpl));
	if (!tmpl)
		return NULL;
	
	tmpl->sigoplimit = USHRT_MAX;
	tmpl->sizelimit = ULONG_MAX;
	tmpl->weightlimit = INT64_MAX;
	
	tmpl->maxtime = 0xffffffff;
	tmpl->maxtimeoff = 0x7fff;
	tmpl->mintimeoff = -0x7fff;
	tmpl->expires = 0x7fff;
	
	return tmpl;
}

uint32_t blktmpl_addcaps(const blktemplate_t *tmpl) {
	// TODO: make this a lot more flexible for merging
	// For now, it's a simple "filled" vs "not filled"
	if (tmpl->version)
		return 0;
	return GBT_CBTXN | GBT_WORKID | BMM_TIMEINC | BMM_CBAPPEND | BMM_VERFORCE | BMM_VERDROP | BMAb_COINBASE | BMAb_TRUNCATE;
}

const struct blktmpl_longpoll_req *blktmpl_get_longpoll(blktemplate_t *tmpl) {
	if (!tmpl->lp.id)
		return NULL;
	return &tmpl->lp;
}

bool blktmpl_get_submitold(blktemplate_t *tmpl) {
	return tmpl->submitold;
}

void blktxn_clean(struct blktxn_t * const bt) {
	free(bt->data);
	free(bt->hash);
	free(bt->hash_);
	free(bt->depends);
	free(bt->txid);
}

static
void blkaux_clean(struct blkaux_t * const aux) {
	free(aux->auxname);
	free(aux->data);
}

void blktmpl_free(blktemplate_t *tmpl) {
	for (unsigned long i = 0; i < tmpl->txncount; ++i)
		blktxn_clean(&tmpl->txns[i]);
	free(tmpl->txns);
	if (tmpl->cbtxn)
	{
		blktxn_clean(tmpl->cbtxn);
		free(tmpl->cbtxn);
	}
	free(tmpl->_mrklbranch);
	free(tmpl->_witnessmrklroot);
	for (unsigned i = 0; i < tmpl->aux_count; ++i)
		blkaux_clean(&tmpl->auxs[i]);
	free(tmpl->auxs);
	free(tmpl->workid);
	free(tmpl->target);
	free(tmpl->lp.id);
	free(tmpl->lp.uri);
	
	if (tmpl->rules) {
		for (char **currule = tmpl->rules; *currule; ++currule) {
			free(*currule);
		}
		free(tmpl->rules);
	}
	if (tmpl->vbavailable) {
		for (struct blktmpl_vbassoc **curvb = tmpl->vbavailable; *curvb; ++curvb) {
			free((*curvb)->name);
			free(*curvb);
		}
		free(tmpl->vbavailable);
	}
	
	free(tmpl);
}

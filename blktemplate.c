#define _BSD_SOURCE

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

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
	"generate",
	"time/increment",
	"time/decrement",
	"transactions/add",
	"prevblock",
	NULL,
	
	"submit/hash",
	"submit/coinbase",
	"submit/truncate",
	"share/coinbase",
	"share/merkle",
	"share/truncate",
};

const char *blktmpl_capabilityname(gbt_capabilities_t caps) {
	for (int i = 0; i < sizeof(capnames); ++i)
		if (caps & (1 << i))
			return capnames[i];
	return NULL;
}

blktemplate_t *blktmpl_create() {
	blktemplate_t *tmpl;
	tmpl = calloc(1, sizeof(*tmpl));
	
	tmpl->sigoplimit = USHRT_MAX;
	tmpl->sizelimit = ULONG_MAX;
	
	tmpl->maxtime = 0xffffffff;
	tmpl->maxtimeoff = 0x7fff;
	tmpl->mintimeoff = -0x7fff;
	tmpl->maxnonce = 0xffffffff;
	tmpl->expires = 0x7fff;
	
	return tmpl;
}

gbt_capabilities_t blktmpl_addcaps(const blktemplate_t *tmpl) {
	// TODO: make this a lot more flexible for merging
	// For now, it's a simple "filled" vs "not filled"
	if (tmpl->version)
		return 0;
	return GBT_CBTXN | GBT_WORKID | BMM_CBAPPEND | BMM_CBSET | BMM_TIMEINC | BMM_TIMEDEC;
}

static
void blktxn_free(struct blktxn_t *bt) {
	free(bt->data);
	free(bt->hash);
	free(bt->depends);
}

void blktmpl_free(blktemplate_t *tmpl) {
	for (int i = 0; i < tmpl->txncount; ++i)
		blktxn_free(&tmpl->txns[i]);
	free(tmpl->txns);
	if (tmpl->cbtxn)
	{
		blktxn_free(tmpl->cbtxn);
		free(tmpl->cbtxn);
	}
	// TODO: maybe free auxnames[0..n]? auxdata too
	free(tmpl->auxnames);
	free(tmpl->auxdata);
	free(tmpl->workid);
	free(tmpl);
}

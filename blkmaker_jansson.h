#ifndef BLKMAKER_JANSSON_H
#define BLKMAKER_JANSSON_H

#include <jansson.h>

#include <blktemplate.h>

extern json_t *blktmpl_request_jansson(gbt_capabilities_t extracaps);
extern const char *blktmpl_add_jansson(blktemplate_t *, json_t *, time_t time_rcvd);
extern json_t *blkmk_submit_jansson(blktemplate_t *, const unsigned char *data, blknonce_t);

#endif

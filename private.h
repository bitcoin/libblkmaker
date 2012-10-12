#ifndef BLKMK_PRIVATE_H
#define BLKMK_PRIVATE_H

#include <stdbool.h>
#include <string.h>

// hex.c
extern void _blkmk_bin2hex(char *out, const void *data, size_t datasz);
extern bool _blkmk_hex2bin(void *o, const char *x, size_t len);

#endif

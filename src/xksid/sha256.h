#ifndef XKSID_SHA256_H
#define XKSID_SHA256_H

#include <stddef.h>
#include <stdint.h>

void xk_sha256(const unsigned char *data, size_t len, unsigned char out[32]);

#endif

#ifndef XKSID_TOK_H
#define XKSID_TOK_H

#include <stddef.h>
#include <stdint.h>

typedef struct xt_tok xt_tok;

xt_tok *xt_load(const char *bundle); // NULL if the file is missing or not a bundle
void    xt_free(xt_tok *t);
int32_t xt_n_vocab(const xt_tok *t);

// Token ids of the text, written to *ids (grown with realloc, *cap in ids). Returns the count.
size_t xt_tokenize(const xt_tok *t, const unsigned char *text, size_t len, int32_t **ids, size_t *cap);

#endif

// Byte-level BPE tokenizer for the vocabulary packed by xksid-tokpack.
// It follows llama.cpp for a "gpt2" vocabulary with the "lfm2" pre-tokenizer:
// the text is split by the LLAMA3 rule, each piece is written in byte-level
// form, a piece that is itself a vocabulary entry is one token, and any other
// piece is merged pair by pair, lowest merge rank first, leftmost on a tie.

#include "tok.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { LETTER = 1, NUMBER = 2, SPACE = 4, N_CLASS = 0x110000 };

struct xt_tok {
    unsigned char *file; // the whole bundle
    const unsigned char *cls;
    int32_t  n_vocab, n_merges;
    const unsigned char **v_text; // token texts
    uint16_t *v_len;
    const unsigned char **m_left, **m_right; // merge pairs, index = rank
    uint16_t *m_llen, *m_rlen;
    int32_t  *v_slot, *m_slot; // open addressing, -1 = empty
    size_t    v_mask, m_mask;
    uint32_t  byte_cp[256]; // byte -> code point of its byte-level character
    const unsigned char *v_type; // 1 normal, 3 control, 4 user defined, 5 unused
    int32_t   special[64];       // user-defined tokens, longest text first
    int       n_special;
    unsigned char first[256];    // first[b]: some user-defined token starts with byte b
};

static uint64_t hash(const unsigned char *p, size_t n, uint64_t h) {
    for (size_t i = 0; i < n; i++) {
        h = (h ^ p[i]) * 0x100000001b3u;
    }
    return h;
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24;
}

static int32_t vocab_find(const xt_tok *t, const unsigned char *s, size_t n) {
    for (size_t i = (size_t) hash(s, n, 0xcbf29ce484222325u) & t->v_mask;; i = (i + 1) & t->v_mask) {
        const int32_t id = t->v_slot[i];
        if (id < 0) {
            return -1;
        }
        if (t->v_len[id] == n && memcmp(t->v_text[id], s, n) == 0) {
            return id;
        }
    }
}

static int32_t merge_rank(const xt_tok *t, const unsigned char *l, size_t ln, const unsigned char *r, size_t rn) {
    const uint64_t h = hash(r, rn, hash(l, ln, 0xcbf29ce484222325u) * 31u + 7u);
    for (size_t i = (size_t) h & t->m_mask;; i = (i + 1) & t->m_mask) {
        const int32_t k = t->m_slot[i];
        if (k < 0) {
            return INT32_MAX;
        }
        if (t->m_llen[k] == ln && t->m_rlen[k] == rn && memcmp(t->m_left[k], l, ln) == 0 && memcmp(t->m_right[k], r, rn) == 0) {
            return k;
        }
    }
}

void xt_free(xt_tok *t) {
    if (t == NULL) {
        return;
    }
    free(t->file);
    free(t->v_text);
    free(t->v_len);
    free(t->m_left);
    free(t->m_right);
    free(t->m_llen);
    free(t->m_rlen);
    free(t->v_slot);
    free(t->m_slot);
    free(t);
}

xt_tok *xt_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    xt_tok *t = calloc(1, sizeof *t);
    if (t == NULL || size < 24 + N_CLASS || (t->file = malloc((size_t) size)) == NULL ||
        fread(t->file, 1, (size_t) size, f) != (size_t) size) {
        fclose(f);
        xt_free(t);
        return NULL;
    }
    fclose(f);
    const unsigned char *p = t->file, *end = t->file + size;
    if (memcmp(p, "XKSIDTOK", 8) != 0 || rd32(p + 8) != 2 || rd32(p + 20) != N_CLASS) {
        xt_free(t);
        return NULL;
    }
    t->n_vocab  = (int32_t) rd32(p + 12);
    t->n_merges = (int32_t) rd32(p + 16);
    t->cls      = p + 24;
    p += 24 + N_CLASS;

    const size_t nv = (size_t) t->n_vocab, nm = (size_t) t->n_merges;
    if (p + nv > end) {
        xt_free(t);
        return NULL;
    }
    t->v_type = p;
    p += nv;
    for (t->v_mask = 1; t->v_mask < nv * 2; t->v_mask <<= 1) {
    }
    for (t->m_mask = 1; t->m_mask < nm * 2; t->m_mask <<= 1) {
    }
    t->v_text  = malloc(nv * sizeof *t->v_text);
    t->v_len   = malloc(nv * sizeof *t->v_len);
    t->m_left  = malloc(nm * sizeof *t->m_left);
    t->m_right = malloc(nm * sizeof *t->m_right);
    t->m_llen  = malloc(nm * sizeof *t->m_llen);
    t->m_rlen  = malloc(nm * sizeof *t->m_rlen);
    t->v_slot  = malloc(t->v_mask * sizeof *t->v_slot);
    t->m_slot  = malloc(t->m_mask * sizeof *t->m_slot);
    if (!t->v_text || !t->v_len || !t->m_left || !t->m_right || !t->m_llen || !t->m_rlen || !t->v_slot || !t->m_slot) {
        xt_free(t);
        return NULL;
    }
    memset(t->v_slot, 0xFF, t->v_mask * sizeof *t->v_slot);
    memset(t->m_slot, 0xFF, t->m_mask * sizeof *t->m_slot);
    t->v_mask--;
    t->m_mask--;

    for (size_t i = 0; i < nv; i++) {
        if (p + 2 > end || p + 2 + (p[0] | p[1] << 8) > end) {
            xt_free(t);
            return NULL;
        }
        t->v_len[i]  = (uint16_t) (p[0] | p[1] << 8);
        t->v_text[i] = p + 2;
        p += 2 + t->v_len[i];
        // a later token with the same text replaces an earlier one, as in llama.cpp
        size_t s = (size_t) hash(t->v_text[i], t->v_len[i], 0xcbf29ce484222325u) & t->v_mask;
        while (t->v_slot[s] >= 0 && !(t->v_len[t->v_slot[s]] == t->v_len[i] && memcmp(t->v_text[t->v_slot[s]], t->v_text[i], t->v_len[i]) == 0)) {
            s = (s + 1) & t->v_mask;
        }
        t->v_slot[s] = (int32_t) i;
        // user-defined tokens are matched in the raw text before anything else, longest first
        if (t->v_type[i] == 4 && t->v_len[i] > 0 && t->n_special < 64) {
            int k = t->n_special++;
            for (; k > 0 && t->v_len[t->special[k - 1]] < t->v_len[i]; k--) {
                t->special[k] = t->special[k - 1];
            }
            t->special[k] = (int32_t) i;
            t->first[t->v_text[i][0]] = 1;
        }
    }
    for (size_t i = 0; i < nm; i++) {
        if (p + 4 > end || p + 4 + (p[0] | p[1] << 8) + (p[2] | p[3] << 8) > end) {
            xt_free(t);
            return NULL;
        }
        t->m_llen[i]  = (uint16_t) (p[0] | p[1] << 8);
        t->m_rlen[i]  = (uint16_t) (p[2] | p[3] << 8);
        t->m_left[i]  = p + 4;
        t->m_right[i] = p + 4 + t->m_llen[i];
        p += 4 + t->m_llen[i] + t->m_rlen[i];
        // the first pair of a given text keeps its rank, as in llama.cpp
        if (merge_rank(t, t->m_left[i], t->m_llen[i], t->m_right[i], t->m_rlen[i]) == INT32_MAX) {
            const uint64_t h = hash(t->m_right[i], t->m_rlen[i], hash(t->m_left[i], t->m_llen[i], 0xcbf29ce484222325u) * 31u + 7u);
            size_t s = (size_t) h & t->m_mask;
            while (t->m_slot[s] >= 0) {
                s = (s + 1) & t->m_mask;
            }
            t->m_slot[s] = (int32_t) i;
        }
    }

    // GPT-2 byte-level alphabet: printable bytes are themselves, the others follow from U+0100
    uint32_t next = 256;
    for (int b = 0; b < 256; b++) {
        const int self = (b >= 33 && b <= 126) || (b >= 161 && b <= 172) || (b >= 174 && b <= 255);
        t->byte_cp[b] = self ? (uint32_t) b : next++;
    }
    return t;
}

int32_t xt_n_vocab(const xt_tok *t) {
    return t->n_vocab;
}

// one code point; a malformed byte is itself
static size_t decode(const unsigned char *p, size_t left, uint32_t *cp) {
    const unsigned char c = p[0];
    const size_t n = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 1;
    if (n == 1 || n > left) {
        *cp = c;
        return 1;
    }
    uint32_t v = c & (0xFFu >> (n + 1));
    for (size_t i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) {
            *cp = c;
            return 1;
        }
        v = v << 6 | (p[i] & 0x3Fu);
    }
    *cp = v < N_CLASS ? v : c;
    return v < N_CLASS ? n : 1;
}

typedef struct {
    const xt_tok *t;
    const unsigned char *s;
    size_t len;
} text;

static int class_at(const text *x, size_t i, size_t *n) {
    if (i >= x->len) {
        *n = 0;
        return -1;
    }
    uint32_t cp;
    *n = decode(x->s + i, x->len - i, &cp);
    return x->t->cls[cp];
}

static int is_newline(const text *x, size_t i) {
    return i < x->len && (x->s[i] == '\r' || x->s[i] == '\n');
}

static size_t run(const text *x, size_t i, int mask, int want) {
    size_t n;
    for (int c; (c = class_at(x, i, &n)) >= 0 && ((c & mask) != 0) == want; i += n) {
    }
    return i;
}

// end of the piece that starts at i, by the alternatives of the LLAMA3 rule in order
static size_t piece_end(const text *x, size_t i) {
    const unsigned char *s = x->s;
    size_t n, n2;
    const int c = class_at(x, i, &n);
    // 's 't 're 've 'm 'll 'd
    if (s[i] == '\'' && i + 1 < x->len) {
        const int a = s[i + 1] | 0x20, b = i + 2 < x->len ? s[i + 2] | 0x20 : 0;
        if (a == 's' || a == 't') {
            return i + 2;
        }
        if ((a == 'r' && b == 'e') || (a == 'v' && b == 'e')) {
            return i + 3;
        }
        if (a == 'm') {
            return i + 2;
        }
        if (a == 'l' && b == 'l') {
            return i + 3;
        }
        if (a == 'd') {
            return i + 2;
        }
    }
    // one optional character that is no newline, letter or number, then letters
    if (c & LETTER) {
        return run(x, i, LETTER, 1);
    }
    if (!(c & NUMBER) && !is_newline(x, i) && (class_at(x, i + n, &n2) & LETTER) && n2 > 0) {
        return run(x, i + n, LETTER, 1);
    }
    // one to three numbers
    if (c & NUMBER) {
        size_t e = i + n;
        for (int k = 1; k < 3 && (class_at(x, e, &n2) & NUMBER) && n2 > 0; k++) {
            e += n2;
        }
        return e;
    }
    // an optional space, characters that are no whitespace, letter or number, then newlines
    {
        size_t start = i;
        if (s[i] == ' ') {
            const int c2 = class_at(x, i + 1, &n2);
            if (c2 >= 0 && !(c2 & (SPACE | LETTER | NUMBER))) {
                start = i + 1;
            }
        }
        const int c3 = class_at(x, start, &n2);
        if (c3 >= 0 && !(c3 & (SPACE | LETTER | NUMBER))) {
            size_t e = run(x, start, SPACE | LETTER | NUMBER, 0);
            while (is_newline(x, e)) {
                e++;
            }
            return e;
        }
    }
    // whitespace: up to its last newline; else all but the last character unless the text
    // ends; else the whole run
    const size_t e = run(x, i, SPACE, 1);
    if (e > i) {
        size_t last = 0;
        for (size_t k = i; k < e; k++) {
            if (is_newline(x, k)) {
                last = k + 1;
            }
        }
        if (last > 0) {
            return last;
        }
        if (e == x->len) {
            return e;
        }
        size_t k = i, prev = i;
        while (k < e) {
            prev = k;
            class_at(x, k, &n2);
            k += n2;
        }
        return prev > i ? prev : e;
    }
    return i + (n > 0 ? n : 1);
}

// tokens of one stretch of text that holds no user-defined token; returns the new count
static size_t fragment(const xt_tok *t, const unsigned char *s, size_t len, int32_t **ids, size_t *cap, size_t count) {
    if (len == 0) {
        return count;
    }
    const text x = {t, s, len};
    unsigned char *enc = malloc(2 * len + 2);
    int32_t *off = malloc((len + 1) * 5 * sizeof *off); // per symbol: offset, length, next, previous, rank
    if (enc == NULL || off == NULL) {
        free(enc);
        free(off);
        return count;
    }
    int32_t *slen = off + (len + 1), *next = slen + (len + 1), *prev = next + (len + 1), *rank = prev + (len + 1);

    for (size_t i = 0; i < len;) {
        const size_t e = piece_end(&x, i);
        // byte-level form of the piece, one symbol per byte
        size_t m = 0;
        int32_t n = 0;
        for (size_t k = i; k < e; k++) {
            const uint32_t cp = t->byte_cp[s[k]];
            off[n] = (int32_t) m;
            if (cp < 0x80) {
                enc[m++] = (unsigned char) cp;
            } else {
                enc[m++] = (unsigned char) (0xC0 | cp >> 6);
                enc[m++] = (unsigned char) (0x80 | (cp & 0x3F));
            }
            slen[n] = (int32_t) m - off[n];
            n++;
        }
        i = e;
        if (count + (size_t) n + 1 > *cap) {
            *cap = (*cap + (size_t) n + 1) * 2;
            int32_t *grown = realloc(*ids, *cap * sizeof **ids);
            if (grown == NULL) {
                break;
            }
            *ids = grown;
        }
        const int32_t whole = vocab_find(t, enc, m);
        if (whole >= 0) {
            (*ids)[count++] = whole;
            continue;
        }
        for (int32_t k = 0; k < n; k++) {
            next[k] = k + 1 < n ? k + 1 : -1;
            prev[k] = k - 1;
            rank[k] = k + 1 < n ? merge_rank(t, enc + off[k], (size_t) slen[k], enc + off[k + 1], (size_t) slen[k + 1]) : INT32_MAX;
        }
        for (;;) {
            int32_t best = -1;
            for (int32_t k = 0; k >= 0; k = next[k]) {
                if (rank[k] != INT32_MAX && (best < 0 || rank[k] < rank[best])) {
                    best = k;
                }
            }
            if (best < 0) {
                break;
            }
            const int32_t r = next[best];
            slen[best] += slen[r];
            next[best] = next[r];
            if (next[r] >= 0) {
                prev[next[r]] = best;
            }
            const int32_t nx = next[best], pv = prev[best];
            rank[best] = nx >= 0 ? merge_rank(t, enc + off[best], (size_t) slen[best], enc + off[nx], (size_t) slen[nx]) : INT32_MAX;
            if (pv >= 0) {
                rank[pv] = merge_rank(t, enc + off[pv], (size_t) slen[pv], enc + off[best], (size_t) slen[best]);
            }
        }
        for (int32_t k = 0; k >= 0; k = next[k]) {
            const int32_t id = vocab_find(t, enc + off[k], (size_t) slen[k]);
            if (id >= 0) {
                (*ids)[count++] = id;
            }
        }
    }
    free(enc);
    free(off);
    return count;
}

size_t xt_tokenize(const xt_tok *t, const unsigned char *s, size_t len, int32_t **ids, size_t *cap) {
    size_t count = 0, start = 0;
    for (size_t i = 0; i < len; i++) {
        if (!t->first[s[i]]) {
            continue;
        }
        for (int k = 0; k < t->n_special; k++) {
            const int32_t id = t->special[k];
            const size_t  n  = t->v_len[id];
            if (n > len - i || memcmp(s + i, t->v_text[id], n) != 0) {
                continue;
            }
            count = fragment(t, s + start, i - start, ids, cap, count);
            if (count + 1 > *cap) {
                *cap = (*cap + 16) * 2;
                int32_t *grown = realloc(*ids, *cap * sizeof **ids);
                if (grown == NULL) {
                    return count;
                }
                *ids = grown;
            }
            (*ids)[count++] = id;
            i    += n - 1;
            start = i + 1;
            break;
        }
    }
    return fragment(t, s + start, len - start, ids, cap, count);
}

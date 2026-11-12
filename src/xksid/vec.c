// Layer L6: scoring text with the precalculated decision vectors of a model.
// No model runs here. Each token id selects one row of the table; rows are
// summed in blocks of 16 tokens, four blocks make a window, and a head turns
// the mean vector of a window into the model's yes-minus-no logit.

#define _GNU_SOURCE

#include "vec.h"

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// ---- kernels

void xv_add_scalar(float *acc, const float *row, size_t n) {
    for (size_t i = 0; i < n; i++) {
        acc[i] += row[i];
    }
}

float xv_dot_scalar(const float *a, const float *b, size_t n) {
    float s = 0.0f;
    for (size_t i = 0; i < n; i++) {
        s += a[i] * b[i];
    }
    return s;
}

#if defined(__x86_64__)
#include <immintrin.h>

__attribute__((target("avx2,fma")))
static void add_avx2(float *acc, const float *row, size_t n) {
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        _mm256_storeu_ps(acc + i,      _mm256_add_ps(_mm256_loadu_ps(acc + i),      _mm256_loadu_ps(row + i)));
        _mm256_storeu_ps(acc + i + 8,  _mm256_add_ps(_mm256_loadu_ps(acc + i + 8),  _mm256_loadu_ps(row + i + 8)));
        _mm256_storeu_ps(acc + i + 16, _mm256_add_ps(_mm256_loadu_ps(acc + i + 16), _mm256_loadu_ps(row + i + 16)));
        _mm256_storeu_ps(acc + i + 24, _mm256_add_ps(_mm256_loadu_ps(acc + i + 24), _mm256_loadu_ps(row + i + 24)));
    }
    for (; i + 8 <= n; i += 8) {
        _mm256_storeu_ps(acc + i, _mm256_add_ps(_mm256_loadu_ps(acc + i), _mm256_loadu_ps(row + i)));
    }
    for (; i < n; i++) {
        acc[i] += row[i];
    }
}

// four accumulators: the multiply-add of one does not wait for the previous one
__attribute__((target("avx2,fma")))
static float dot_avx2(const float *a, const float *b, size_t n) {
    __m256 s0 = _mm256_setzero_ps(), s1 = s0, s2 = s0, s3 = s0;
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        s0 = _mm256_fmadd_ps(_mm256_loadu_ps(a + i),      _mm256_loadu_ps(b + i),      s0);
        s1 = _mm256_fmadd_ps(_mm256_loadu_ps(a + i + 8),  _mm256_loadu_ps(b + i + 8),  s1);
        s2 = _mm256_fmadd_ps(_mm256_loadu_ps(a + i + 16), _mm256_loadu_ps(b + i + 16), s2);
        s3 = _mm256_fmadd_ps(_mm256_loadu_ps(a + i + 24), _mm256_loadu_ps(b + i + 24), s3);
    }
    for (; i + 8 <= n; i += 8) {
        s0 = _mm256_fmadd_ps(_mm256_loadu_ps(a + i), _mm256_loadu_ps(b + i), s0);
    }
    const __m256 s  = _mm256_add_ps(_mm256_add_ps(s0, s1), _mm256_add_ps(s2, s3));
    __m128       lo = _mm_add_ps(_mm256_castps256_ps128(s), _mm256_extractf128_ps(s, 1));
    lo = _mm_add_ps(lo, _mm_movehl_ps(lo, lo));
    lo = _mm_add_ss(lo, _mm_shuffle_ps(lo, lo, 1));
    float sum = _mm_cvtss_f32(lo);
    for (; i < n; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

static int have_avx2_fma(void) {
    static int known = -1;
    if (known < 0) {
        known = __builtin_cpu_supports("avx2") && __builtin_cpu_supports("fma");
    }
    return known;
}

void xv_add(float *acc, const float *row, size_t n) {
    if (have_avx2_fma()) {
        add_avx2(acc, row, n);
    } else {
        xv_add_scalar(acc, row, n);
    }
}

float xv_dot(const float *a, const float *b, size_t n) {
    return have_avx2_fma() ? dot_avx2(a, b, n) : xv_dot_scalar(a, b, n);
}

const char *xv_kernel(void) {
    return have_avx2_fma() ? "avx2+fma" : "scalar";
}

#else

void xv_add(float *acc, const float *row, size_t n) {
    xv_add_scalar(acc, row, n);
}

float xv_dot(const float *a, const float *b, size_t n) {
    return xv_dot_scalar(a, b, n);
}

const char *xv_kernel(void) {
    return "scalar";
}

#endif

// ---- table

int xv_open(xv_table *t, const char *path, int32_t dim) {
    memset(t, 0, sizeof *t);
    const int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || dim <= 0 || st.st_size <= 0 || (size_t) st.st_size % ((size_t) dim * sizeof(float)) != 0) {
        close(fd);
        return -1;
    }
    void *p = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        return -1;
    }
    t->rows  = p;
    t->bytes = (size_t) st.st_size;
    t->dim   = dim;
    t->n     = (int32_t) ((size_t) st.st_size / ((size_t) dim * sizeof(float)));
    return 0;
}

void xv_close(xv_table *t) {
    if (t->rows != NULL) {
        munmap((void *) (uintptr_t) t->rows, t->bytes);
    }
    memset(t, 0, sizeof *t);
}

// ---- head file: "XKSIDHED", i32 dim, i32 normalise, f32 bias, f32 temperature, f32 cut,
//      f32 w[dim], f32 mean[dim]

int xv_head_load(xv_head *h, const char *path) {
    memset(h, 0, sizeof *h);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    char magic[8];
    int  ok = fread(magic, 1, 8, f) == 8 && memcmp(magic, "XKSIDHED", 8) == 0 && fread(&h->dim, 4, 1, f) == 1 &&
              fread(&h->normalise, 4, 1, f) == 1 && fread(&h->bias, 4, 1, f) == 1 && fread(&h->temperature, 4, 1, f) == 1 && fread(&h->cut, 4, 1, f) == 1 &&
              h->dim > 0 && h->dim <= 65536 && h->temperature > 0.0f;
    if (ok) {
        const size_t d = (size_t) h->dim;
        h->w    = malloc(d * sizeof *h->w);
        h->mean = malloc(d * sizeof *h->mean);
        ok      = h->w != NULL && h->mean != NULL && fread(h->w, sizeof *h->w, d, f) == d && fread(h->mean, sizeof *h->mean, d, f) == d;
    }
    fclose(f);
    if (!ok) {
        xv_head_free(h);
        return -1;
    }
    return 0;
}

int xv_head_save(const xv_head *h, const char *path) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    const int ok = fwrite("XKSIDHED", 1, 8, f) == 8 && fwrite(&h->dim, 4, 1, f) == 1 && fwrite(&h->normalise, 4, 1, f) == 1 &&
                   fwrite(&h->bias, 4, 1, f) == 1 && fwrite(&h->temperature, 4, 1, f) == 1 && fwrite(&h->cut, 4, 1, f) == 1 &&
                   fwrite(h->w, sizeof *h->w, (size_t) h->dim, f) == (size_t) h->dim &&
                   fwrite(h->mean, sizeof *h->mean, (size_t) h->dim, f) == (size_t) h->dim;
    return fclose(f) == 0 && ok ? 0 : -1;
}

void xv_head_free(xv_head *h) {
    free(h->w);
    free(h->mean);
    memset(h, 0, sizeof *h);
}

// ---- pooling and scoring

static const float *row_of(const xv_table *t, int32_t id) {
    return t->rows + (size_t) (id >= 0 && id < t->n ? id : 0) * (size_t) t->dim;
}

static void block_sum(const xv_table *t, const int32_t *ids, size_t n, float *out) {
    const size_t d = (size_t) t->dim;
    memset(out, 0, d * sizeof *out);
    for (size_t i = 0; i < n; i++) {
        xv_add(out, row_of(t, ids[i]), d);
    }
}

void xv_pool(const xv_table *t, const int32_t *ids, size_t n, float *out) {
    const size_t d = (size_t) t->dim;
    float *block = malloc(d * sizeof *block);
    memset(out, 0, d * sizeof *out);
    for (size_t i = 0; block != NULL && i < n; i += XV_BLOCK) {
        block_sum(t, ids + i, n - i < XV_BLOCK ? n - i : XV_BLOCK, block);
        xv_add(out, block, d);
    }
    free(block);
    const float inv = n > 0 ? 1.0f / (float) n : 0.0f;
    for (size_t i = 0; i < d; i++) {
        out[i] *= inv;
    }
}

// logit of a window from the sum of its rows (length len) over count tokens
static double head_logit(const xv_head *h, const float *sum, size_t count, double len) {
    const double scale = !h->normalise ? 1.0 / (double) count : len > 0.0 ? 1.0 / len : 0.0;
    return (double) xv_dot(h->w, sum, (size_t) h->dim) * scale + (double) h->bias;
}

// ---- benign exemplars: unit vectors of windows the operator marked as false positives

int xv_exemplars_load(xv_exemplars *e, const char *path, int32_t dim) {
    memset(e, 0, sizeof *e);
    e->dim = dim;
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 0; // no feedback yet
    }
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    const size_t row = (size_t) dim * sizeof(float);
    e->n    = size > 0 ? (size_t) size / row : 0;
    e->rows = e->n ? malloc(e->n * row) : NULL;
    const int ok = e->n == 0 || (e->rows != NULL && fread(e->rows, row, e->n, f) == e->n);
    fclose(f);
    if (!ok) {
        free(e->rows);
        e->rows = NULL;
        e->n    = 0;
        return -1;
    }
    return 0;
}

void xv_exemplars_free(xv_exemplars *e) {
    free(e->rows);
    free(e->em);
    memset(e, 0, sizeof *e);
}

void xv_exemplars_bind(xv_exemplars *e, const xv_head *h) {
    const size_t d = (size_t) h->dim;
    e->mm = (double) xv_dot(h->mean, h->mean, d);
    e->em = e->n ? malloc(e->n * sizeof *e->em) : NULL;
    for (size_t i = 0; e->em != NULL && i < e->n; i++) {
        e->em[i] = (double) xv_dot(e->rows + i * d, h->mean, d);
    }
    if (e->em == NULL) {
        e->n = 0;
    }
}

// Every window direction shares one large component, the mean direction of recorded text, so
// plain cosines are all close to 1. The comparison is made after taking that mean away:
// cos(u - m, e - m) with |u| = |e| = 1, expanded so that it costs one dot product per exemplar.
static int is_benign(const xv_exemplars *e, const xv_head *h, const float *sum, double len, size_t d) {
    if (len <= 0.0 || e->n == 0) {
        return 0;
    }
    const double um = (double) xv_dot(sum, h->mean, d) / len, uu = 1.0 - 2.0 * um + e->mm;
    for (size_t i = 0; i < e->n; i++) {
        const double ue = (double) xv_dot(sum, e->rows + i * d, d) / len;
        const double ee = 1.0 - 2.0 * e->em[i] + e->mm;
        if (uu > 0.0 && ee > 0.0 && (ue - um - e->em[i] + e->mm) / sqrt(uu * ee) >= (double) e->cos) {
            return 1;
        }
    }
    return 0;
}

void xv_window_unit(const xv_table *t, const int32_t *ids, size_t n, size_t at, float *out) {
    const size_t d = (size_t) t->dim, end = at + XV_WINDOW < n ? at + XV_WINDOW : n;
    memset(out, 0, d * sizeof *out);
    for (size_t i = at; i < end; i++) {
        xv_add(out, row_of(t, ids[i]), d);
    }
    const double len = sqrt((double) xv_dot(out, out, d));
    for (size_t i = 0; i < d; i++) {
        out[i] = len > 0.0 ? (float) ((double) out[i] / len) : 0.0f;
    }
}

double xv_score(const xv_table *t, const xv_head *h, const xv_exemplars *benign, const int32_t *ids, size_t n, size_t *at, size_t *vetoed) {
    const size_t d = (size_t) t->dim;
    *at     = 0;
    *vetoed = 0;
    // A text of a few tokens is not a window: its pooled vector is nearly one token's own
    // vector, which the head was never fitted to. On recorded tool output 47.2 % of the texts
    // under 8 tokens scored as evidence, against 0.0 to 1.1 % of every longer class.
    if (n < XV_BLOCK || h->dim != t->dim) {
        return XV_NO_SCORE;
    }
    const size_t n_blocks = (n + XV_BLOCK - 1) / XV_BLOCK, per = XV_WINDOW / XV_BLOCK;
    float *blocks = malloc((per + 1) * d * sizeof *blocks); // a ring of block sums, and the window sum
    if (blocks == NULL) {
        return XV_NO_SCORE;
    }
    float *win  = blocks + per * d;
    double best = XV_NO_SCORE;
    for (size_t b = 0; b < n_blocks; b++) {
        const size_t start = b * XV_BLOCK, len = n - start < XV_BLOCK ? n - start : XV_BLOCK;
        block_sum(t, ids + start, len, blocks + (b % per) * d);
        if (b + 1 < per && b + 1 < n_blocks) {
            continue; // the first window is not full yet
        }
        const size_t first = b + 1 >= per ? b + 1 - per : 0; // first block of this window
        memset(win, 0, d * sizeof *win);
        for (size_t k = first; k <= b; k++) {
            xv_add(win, blocks + (k % per) * d, d);
        }
        const size_t count = start + len - first * XV_BLOCK;
        const double norm  = sqrt((double) xv_dot(win, win, d));
        const double logit = head_logit(h, win, count, norm);
        if (logit > best) {
            // a window close to one the operator called a false positive does not count
            if (benign != NULL && logit >= (double) benign->floor && is_benign(benign, h, win, norm, d)) {
                (*vetoed)++;
                continue;
            }
            best = logit;
            *at  = first * XV_BLOCK;
        }
    }
    free(blocks);
    return best;
}

#ifndef XKSID_VEC_H
#define XKSID_VEC_H

#include <stddef.h>
#include <stdint.h>

#ifndef XV_BLOCK_TOKENS
#define XV_BLOCK_TOKENS 16
#endif

enum {
    XV_BLOCK  = XV_BLOCK_TOKENS,     // tokens per block
    XV_WINDOW = 4 * XV_BLOCK_TOKENS, // tokens per window: four blocks, so windows step by one block
};

// ---- kernels. The plain names pick AVX2 + FMA3 when the CPU has both, else the scalar form.

void        xv_add(float *acc, const float *row, size_t n); // acc[i] += row[i]
float       xv_dot(const float *a, const float *b, size_t n);
void        xv_add_scalar(float *acc, const float *row, size_t n);
float       xv_dot_scalar(const float *a, const float *b, size_t n);
const char *xv_kernel(void); // "avx2+fma" or "scalar"

// ---- the table of decision vectors: n rows of dim floats, row t = token t, mapped read only

typedef struct {
    const float *rows;
    size_t       bytes;
    int32_t      n, dim;
} xv_table;

int  xv_open(xv_table *t, const char *path, int32_t dim); // 0 on success
void xv_close(xv_table *t);

// ---- the head: turns the pooled vector of a window into the model's yes-minus-no logit

typedef struct {
    int32_t dim;
    int32_t normalise;   // 1: the pooled vector is scaled to length 1 before the dot product
    float   bias;
    float   temperature; // of the model's two-way softmax
    float   cut;         // logit that 1 plain recorded window in 500 reached when the head was fitted
    float  *w;
    float  *mean;        // mean direction of plain recorded windows: what all windows have in common
} xv_head;

int  xv_head_load(xv_head *h, const char *path); // 0 on success
int  xv_head_save(const xv_head *h, const char *path);
void xv_head_free(xv_head *h);

// Mean vector of ids[0..n) into out (dim floats), blocks of XV_BLOCK summed first.
void xv_pool(const xv_table *t, const int32_t *ids, size_t n, float *out);

// ---- benign exemplars: unit vectors of windows the operator marked as false positives.
// A window at or above floor whose direction is within cos of an exemplar is not counted.

typedef struct {
    float  *rows; // n rows of dim floats, each of length 1
    size_t  n;
    int32_t dim;
    float   cos;   // cosine, after the mean direction is taken away, at or above which a window matches
    float   floor; // logit below which no window is compared: it could not alert anyway
    double *em;    // per exemplar: its dot product with the mean direction
    double  mm;    // the mean direction with itself
} xv_exemplars;

int  xv_exemplars_load(xv_exemplars *e, const char *path, int32_t dim); // 0 on success, a missing file is empty
void xv_exemplars_bind(xv_exemplars *e, const xv_head *h);              // after loading, before scoring
void xv_exemplars_free(xv_exemplars *e);

// Direction (length 1) of the window that starts at token at: what feedback stores.
void xv_window_unit(const xv_table *t, const int32_t *ids, size_t n, size_t at, float *out);

#define XV_NO_SCORE (-1e30)

// Scores every window of the ids. Returns the highest logit, XV_NO_SCORE if no window counts;
// *at is the index of the first token of that window, *vetoed the number of windows set aside
// by benign exemplars (benign may be NULL). A text shorter than a window is one window; a
// text shorter than one block is not scored.
double xv_score(const xv_table *t, const xv_head *h, const xv_exemplars *benign, const int32_t *ids, size_t n, size_t *at, size_t *vetoed);

#endif

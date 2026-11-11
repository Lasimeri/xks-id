// xksid-fit: builds labelled windows and fits the head of layer L6. Offline tool.
//
//   windows BUNDLE PHRASES PARTS LIST N OUT
//       Tokenises the turn files named in LIST, takes every window (four blocks, step one
//       block), draws N of them and writes OUT.i32 (token ids) and OUT.kind (N bytes).
//       Every third window gets a phrase written into it at a random place:
//       kind 0 = recorded text only, 1 = a phrase composed from the lists in PARTS,
//       2 = a line of PHRASES. Lines of PHRASES are never trained on: they measure
//       wording the head has not seen.
//   fit TABLE LOGITS WINDOWS KIND LABELS TEMPERATURE HEAD
//       LABELS holds the model's yes and no logits of each window (xksid-distil label).
//       Fits a linear head on the pooled vector (H1) and on the pooled vector scaled to
//       length 1 (H2) by ridge regression, compares both with the per-token baseline H0
//       on windows held out of the fit, and writes the better head to HEAD.

#define _GNU_SOURCE

#include "tok.h"
#include "vec.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { W = XV_WINDOW, STEP = XV_BLOCK, TRAIN = 0, VAL = 1, TEST = 2 };

static _Noreturn void fail(const char *msg) {
    fprintf(stderr, "xksid-fit: %s\n", msg);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (p == NULL) {
        fail("out of memory");
    }
    return p;
}

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "xksid-fit: cannot read %s\n", path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = xmalloc((size_t) size + 1);
    *len = fread(buf, 1, (size_t) size, f);
    buf[*len] = 0;
    fclose(f);
    return buf;
}

static uint64_t g_rng = 0x2545F4914F6CDD1Du;

static uint64_t rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

static void save(const char *base, const char *ext, const void *data, size_t bytes) {
    char path[1024];
    snprintf(path, sizeof path, "%s%s", base, ext);
    FILE *f = fopen(path, "wb");
    if (f == NULL || fwrite(data, 1, bytes, f) != bytes || fclose(f) != 0) {
        fail("cannot write the output");
    }
}

static int cmd_windows(char **a) {
    xt_tok *tok = xt_load(a[0]);
    if (tok == NULL) {
        fail("not a tokenizer bundle");
    }
    const size_t want = (size_t) atol(a[4]);
    size_t   list_len, phr_len, n_win = 0, cap_win = 0, cap = 0;
    char    *list = (char *) slurp(a[3], &list_len);
    int32_t *all = NULL, *ids = NULL;
    for (char *path = strtok(list, "\n"); path != NULL; path = strtok(NULL, "\n")) {
        size_t         len;
        unsigned char *buf  = slurp(path, &len);
        size_t         head = 0; // skip XKS-Memory's header line
        while (head < len && buf[head] != '\n') {
            head++;
        }
        head = head < len ? head + 1 : len;
        const size_t n = xt_tokenize(tok, buf + head, len - head, &ids, &cap);
        for (size_t s = 0; s + W <= n; s += STEP) {
            if (n_win == cap_win) {
                cap_win = cap_win ? cap_win * 2 : 4096;
                all     = realloc(all, cap_win * W * sizeof *all);
                if (all == NULL) {
                    fail("out of memory");
                }
            }
            memcpy(all + n_win++ * W, ids + s, W * sizeof *all);
        }
        free(buf);
    }
    if (n_win < want) {
        fail("fewer windows in the recorded turns than asked for");
    }
    // a partial shuffle picks the windows
    for (size_t i = 0; i < want; i++) {
        const size_t j = i + (size_t) (rnd() % (n_win - i));
        int32_t      tmp[W];
        memcpy(tmp, all + i * W, sizeof tmp);
        memcpy(all + i * W, all + j * W, sizeof tmp);
        memcpy(all + j * W, tmp, sizeof tmp);
    }

    char  *phrases = (char *) slurp(a[1], &phr_len);
    char  *line[256];
    size_t n_phr = 0;
    for (char *p = strtok(phrases, "\n"); p != NULL && n_phr < 256; p = strtok(NULL, "\n")) {
        line[n_phr++] = p;
    }
    // parts of composed phrases: four lists (addressee, directive, action, tail) separated by "--"
    size_t parts_len, n_part[4] = {0}, sec = 0;
    char  *parts = (char *) slurp(a[2], &parts_len);
    char  *part[4][64];
    for (char *p = strtok(parts, "\n"); p != NULL && sec < 4; p = strtok(NULL, "\n")) {
        if (strcmp(p, "--") == 0) {
            sec++;
        } else if (n_part[sec] < 64) {
            part[sec][n_part[sec]++] = p;
        }
    }
    if (n_phr == 0 || !n_part[0] || !n_part[1] || !n_part[2] || !n_part[3]) {
        fail("need the phrases and four lists of parts");
    }
    unsigned char *kind = xmalloc(want);
    size_t planted = 0, written = 0;
    for (size_t i = 0; i < want; i++) {
        kind[i] = 0;
        if (i % 3 != 0) {
            continue;
        }
        // one planted window in four carries a written phrase: those are only ever tested on
        char      text[1024];
        const int is_written = i % 12 == 0;
        const int tl = is_written ? snprintf(text, sizeof text, " %s", line[rnd() % n_phr])
                                  : snprintf(text, sizeof text, " %s %s %s%s", part[0][rnd() % n_part[0]], part[1][rnd() % n_part[1]],
                                             part[2][rnd() % n_part[2]], part[3][rnd() % n_part[3]]);
        const size_t n = xt_tokenize(tok, (const unsigned char *) text, (size_t) tl, &ids, &cap);
        if (n == 0) {
            continue;
        }
        if (n > W) { // the phrase is longer than a window: the window lies inside it
            memcpy(all + i * W, ids + (size_t) (rnd() % (n - W + 1)), W * sizeof *ids);
        } else {
            memcpy(all + i * W + (size_t) (rnd() % (W - n + 1)), ids, n * sizeof *ids);
        }
        kind[i] = is_written ? 2 : 1;
        planted++;
        written += (size_t) is_written;
    }
    save(a[5], ".i32", all, want * W * sizeof *all);
    save(a[5], ".kind", kind, want);
    printf("%zu windows of %d tokens in the recorded turns, %zu drawn, %zu planted: %zu composed from parts, %zu written (%zu phrases)\n", n_win,
           (int) W, want, planted, planted - written, written, n_phr);
    return 0;
}

// in place: the lower triangle of a becomes L with a = L L^T; 0 if a is positive definite
static int cholesky(double *a, size_t n) {
    for (size_t j = 0; j < n; j++) {
        double s = a[j * n + j];
        for (size_t k = 0; k < j; k++) {
            s -= a[j * n + k] * a[j * n + k];
        }
        if (s <= 0.0) {
            return -1;
        }
        const double diag = sqrt(s);
        a[j * n + j] = diag;
        for (size_t i = j + 1; i < n; i++) {
            double t = a[i * n + j];
            const double *ri = a + i * n, *rj = a + j * n;
            for (size_t k = 0; k < j; k++) {
                t -= ri[k] * rj[k];
            }
            a[i * n + j] = t / diag;
        }
    }
    return 0;
}

static void solve(const double *l, size_t n, double *x) { // x: right side in, solution out
    for (size_t i = 0; i < n; i++) {
        double t = x[i];
        for (size_t k = 0; k < i; k++) {
            t -= l[i * n + k] * x[k];
        }
        x[i] = t / l[i * n + i];
    }
    for (size_t i = n; i-- > 0;) {
        double t = x[i];
        for (size_t k = i + 1; k < n; k++) {
            t -= l[k * n + i] * x[k];
        }
        x[i] = t / l[i * n + i];
    }
}

typedef struct {
    size_t n, pos, tp, fp;
    double r, mae, auc;
} metrics;

static const double *g_key;

static int by_key(const void *a, const void *b) {
    const double x = g_key[*(const size_t *) a], y = g_key[*(const size_t *) b];
    return (x > y) - (x < y);
}

// pred against the model's logit y over the windows of one part; a window counts as yes at logit >= 0
static metrics measure(const double *pred, const double *y, const unsigned char *part, int which, size_t n) {
    metrics m = {0};
    double  sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
    size_t *idx = xmalloc(n * sizeof *idx);
    for (size_t i = 0; i < n; i++) {
        if (part[i] != which) {
            continue;
        }
        idx[m.n++] = i;
        sx += pred[i]; sy += y[i]; sxx += pred[i] * pred[i]; syy += y[i] * y[i]; sxy += pred[i] * y[i];
        m.mae += fabs(pred[i] - y[i]);
        m.pos += y[i] >= 0.0;
        m.tp  += y[i] >= 0.0 && pred[i] >= 0.0;
        m.fp  += y[i] < 0.0 && pred[i] >= 0.0;
    }
    const double k = (double) m.n;
    m.r   = (k * sxy - sx * sy) / sqrt((k * sxx - sx * sx) * (k * syy - sy * sy));
    m.mae /= k;
    // area under the curve: chance that a yes window is ranked above a no window
    g_key = pred;
    qsort(idx, m.n, sizeof *idx, by_key);
    double rank_sum = 0;
    for (size_t i = 0; i < m.n; i++) {
        if (y[idx[i]] >= 0.0) {
            rank_sum += (double) (i + 1);
        }
    }
    const double p = (double) m.pos, q = k - p;
    m.auc = p > 0 && q > 0 ? (rank_sum - p * (p + 1) / 2) / (p * q) : 0.0;
    free(idx);
    return m;
}

static int by_value(const void *a, const void *b) {
    const double x = *(const double *) a, y = *(const double *) b;
    return (x > y) - (x < y);
}

// The logit above which the given share of held-out windows without a planted phrase lies,
// and how many held-out planted windows the model calls yes are at or above it.
static double operating(const char *name, const double *pred, const double *y, const unsigned char *kind, const unsigned char *part,
                        size_t n, double share) {
    double *plain = xmalloc(n * sizeof *plain);
    size_t  m = 0, yes = 0, caught = 0;
    for (size_t i = 0; i < n; i++) {
        if (part[i] == TEST && kind[i] == 0) {
            plain[m++] = pred[i];
        }
    }
    qsort(plain, m, sizeof *plain, by_value);
    const size_t flagged = (size_t) ((double) m * share + 0.5);
    const double cut = plain[m - (flagged > 0 ? flagged : 1)];
    for (size_t i = 0; i < n; i++) {
        if (part[i] == TEST && kind[i] != 0 && y[i] >= 0.0) {
            yes++;
            caught += pred[i] >= cut;
        }
    }
    printf("%-10s flags %zu of %zu plain windows at logit >= %7.3f: catches %zu of %zu (%.1f %%)\n", name, flagged > 0 ? flagged : 1, m, cut,
           caught, yes, 100.0 * (double) caught / (double) yes);
    free(plain);
    return cut;
}

static void report(const char *name, const metrics *m) {
    printf("%-34s r %.4f  mean |error| %.3f  AUC %.4f  catches %zu of %zu model-yes  false yes %zu of %zu\n", name, m->r, m->mae, m->auc,
           m->tp, m->pos, m->fp, m->n - m->pos);
}

// ridge fit of y on the rows of x (n x d floats); returns the validation error, fills w and bias
static double ridge(const float *x, const double *y, const unsigned char *part, size_t n, size_t d, double *w, double *bias, double *pred) {
    double *mu = calloc(d, sizeof *mu), *g = calloc(d * d, sizeof *g), *c = calloc(d, sizeof *c);
    double *l = xmalloc(d * d * sizeof *l), *cand = xmalloc(d * sizeof *cand), *xc = xmalloc(d * sizeof *xc);
    if (mu == NULL || g == NULL || c == NULL) {
        fail("out of memory");
    }
    double ybar = 0, n_train = 0;
    for (size_t i = 0; i < n; i++) {
        if (part[i] == TRAIN) {
            for (size_t j = 0; j < d; j++) {
                mu[j] += x[i * d + j];
            }
            ybar += y[i];
            n_train += 1;
        }
    }
    for (size_t j = 0; j < d; j++) {
        mu[j] /= n_train;
    }
    ybar /= n_train;
    for (size_t i = 0; i < n; i++) {
        if (part[i] != TRAIN) {
            continue;
        }
        for (size_t j = 0; j < d; j++) {
            xc[j] = x[i * d + j] - mu[j];
        }
        const double yc = y[i] - ybar;
        for (size_t j = 0; j < d; j++) {
            const double xj = xc[j];
            double      *gj = g + j * d;
            c[j] += xj * yc;
            for (size_t k = 0; k <= j; k++) {
                gj[k] += xj * xc[k];
            }
        }
    }
    double trace = 0;
    for (size_t j = 0; j < d; j++) {
        trace += g[j * d + j];
    }
    double best = 1e300;
    static const double LAMBDA[] = {1e-4, 1e-3, 1e-2, 1e-1};
    for (size_t t = 0; t < sizeof LAMBDA / sizeof LAMBDA[0]; t++) {
        memcpy(l, g, d * d * sizeof *l);
        for (size_t j = 0; j < d; j++) {
            l[j * d + j] += LAMBDA[t] * trace / (double) d;
        }
        if (cholesky(l, d) != 0) {
            continue;
        }
        memcpy(cand, c, d * sizeof *cand);
        solve(l, d, cand);
        double b = ybar, err = 0, n_val = 0;
        for (size_t j = 0; j < d; j++) {
            b -= cand[j] * mu[j];
        }
        for (size_t i = 0; i < n; i++) {
            if (part[i] == VAL) {
                double p = b;
                for (size_t j = 0; j < d; j++) {
                    p += cand[j] * x[i * d + j];
                }
                err += (p - y[i]) * (p - y[i]);
                n_val += 1;
            }
        }
        err /= n_val;
        printf("    ridge %.0e: validation mean squared error %.4f\n", LAMBDA[t], err);
        if (err < best) {
            best  = err;
            *bias = b;
            memcpy(w, cand, d * sizeof *w);
        }
    }
    for (size_t i = 0; i < n; i++) {
        double p = *bias;
        for (size_t j = 0; j < d; j++) {
            p += w[j] * x[i * d + j];
        }
        pred[i] = p;
    }
    free(mu); free(g); free(c); free(l); free(cand); free(xc);
    return best;
}

static int cmd_fit(char **a) {
    xv_table table;
    if (xv_open(&table, a[0], 2048) != 0) {
        fail("cannot open the table");
    }
    const size_t d = (size_t) table.dim;
    size_t len_l, len_w, len_k, len_y;
    const float   *tl   = (const float *) slurp(a[1], &len_l);
    const int32_t *win  = (const int32_t *) slurp(a[2], &len_w);
    const unsigned char *kind = slurp(a[3], &len_k);
    const float   *lab  = (const float *) slurp(a[4], &len_y);
    const size_t n = len_k;
    if (len_w != n * W * sizeof *win || len_y != n * 2 * sizeof *lab || len_l != (size_t) table.n * 2 * sizeof *tl) {
        fail("the window, kind, label and logit files do not fit together");
    }

    unsigned char *part = xmalloc(n);
    double *y = xmalloc(n * sizeof *y), *p0 = xmalloc(n * sizeof *p0), *p1 = xmalloc(n * sizeof *p1), *p2 = xmalloc(n * sizeof *p2);
    float  *x = xmalloc(n * d * sizeof *x), *xn = xmalloc(n * d * sizeof *xn);
    size_t count[3] = {0}, planted_yes = 0, planted = 0, plain_yes = 0;
    for (size_t i = 0; i < n; i++) {
        part[i] = kind[i] == 2 ? TEST : i % 5 == 4 && kind[i] == 0 ? TEST : i % 5 == 3 ? VAL : TRAIN;
        count[part[i]]++;
        y[i] = (double) lab[2 * i] - (double) lab[2 * i + 1];
        planted     += kind[i] != 0;
        planted_yes += kind[i] != 0 && y[i] >= 0.0;
        plain_yes   += kind[i] == 0 && y[i] >= 0.0;
        // H0: mean of the per-token logits of the table
        double s = 0;
        for (size_t k = 0; k < W; k++) {
            const float dy = tl[2 * win[i * W + k]] - tl[2 * win[i * W + k] + 1];
            s += isnan(dy) ? 0.0 : (double) dy;
        }
        p0[i] = s / (double) W;
        xv_pool(&table, win + i * W, W, x + i * d);
        const double norm = sqrt((double) xv_dot(x + i * d, x + i * d, d));
        for (size_t j = 0; j < d; j++) {
            xn[i * d + j] = (float) ((double) x[i * d + j] / norm);
        }
    }
    printf("%zu windows: %zu train, %zu validation, %zu test; kernel %s\n", n, count[TRAIN], count[VAL], count[TEST], xv_kernel());
    printf("the model says yes on %zu of %zu windows with a planted phrase and on %zu of %zu without\n", planted_yes, planted, plain_yes, n - planted);

    double *w1 = xmalloc(d * sizeof *w1), *w2 = xmalloc(d * sizeof *w2), b1 = 0, b2 = 0;
    printf("H1, linear head on the pooled vector:\n");
    const double e1 = ridge(x, y, part, n, d, w1, &b1, p1);
    printf("H2, linear head on the pooled vector of length 1:\n");
    const double e2 = ridge(xn, y, part, n, d, w2, &b2, p2);

    printf("held-out windows (never used in a fit), against the model's own logit:\n");
    metrics m;
    m = measure(p0, y, part, TEST, n); report("H0 per-token logits, no fit", &m);
    m = measure(p1, y, part, TEST, n); report("H1 pooled vector", &m);
    m = measure(p2, y, part, TEST, n); report("H2 pooled vector, length 1", &m);

    printf("operating points: unseen phrasings the model calls yes, against plain recorded windows flagged:\n");
    const int use2 = e2 < e1;
    double    cut  = 0;
    for (int h = 1; h <= 2; h++) {
        const double *p = h == 1 ? p1 : p2;
        operating(h == 1 ? "H1 1/50" : "H2 1/50", p, y, kind, part, n, 0.02);
        operating(h == 1 ? "H1 1/100" : "H2 1/100", p, y, kind, part, n, 0.01);
        const double c = operating(h == 1 ? "H1 1/500" : "H2 1/500", p, y, kind, part, n, 0.002);
        if ((h == 2) == use2) {
            cut = c;
        }
    }
    xv_head head = {.dim = (int32_t) d, .normalise = use2, .bias = (float) (use2 ? b2 : b1), .temperature = (float) atof(a[5]),
                    .cut = (float) cut, .w = xmalloc(d * sizeof(float)), .mean = xmalloc(d * sizeof(float))};
    // the mean direction of the windows without a planted phrase: what recorded text has in common
    double *mu = calloc(d, sizeof *mu);
    double  n_plain = 0;
    for (size_t i = 0; mu != NULL && i < n; i++) {
        if (kind[i] == 0) {
            for (size_t j = 0; j < d; j++) {
                mu[j] += (double) xn[i * d + j];
            }
            n_plain += 1;
        }
    }
    if (mu == NULL || n_plain == 0) {
        fail("no plain windows");
    }
    for (size_t j = 0; j < d; j++) {
        head.w[j]    = (float) (use2 ? w2[j] : w1[j]);
        head.mean[j] = (float) (mu[j] / n_plain);
    }
    if (xv_head_save(&head, a[6]) != 0) {
        fail("cannot write the head");
    }
    printf("wrote %s: head %s, bias %.6f, temperature %s, alert logit %.3f (1 plain window in 500)\n", a[6], use2 ? "H2" : "H1",
           (double) head.bias, a[5], cut);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 8 && strcmp(argv[1], "windows") == 0) {
        return cmd_windows(argv + 2);
    }
    if (argc == 9 && strcmp(argv[1], "fit") == 0) {
        return cmd_fit(argv + 2);
    }
    fprintf(stderr, "usage: xksid-fit windows BUNDLE PHRASES PARTS LIST N OUT\n"
                    "       xksid-fit fit TABLE LOGITS WINDOWS KIND LABELS TEMPERATURE HEAD\n");
    return 2;
}

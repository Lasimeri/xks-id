// Checks the AVX2 + FMA3 kernels against their scalar references and times both.
//   out/vec_test            test only
//   out/vec_test bench      test, then timings on vectors of 2048 floats
//   out/vec_test bench TABLE  also timings on random rows of a real table

#define _GNU_SOURCE

#include "../src/xksid/vec.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t g_seed = 0x9e3779b97f4a7c15u;

static float rnd(void) { // uniform in [-1, 1)
    g_seed ^= g_seed << 13;
    g_seed ^= g_seed >> 7;
    g_seed ^= g_seed << 17;
    return (float) ((double) (g_seed >> 11) / 4503599627370496.0 - 1.0);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec * 1e-9;
}

typedef void (*add_fn)(float *, const float *, size_t);
typedef float (*dot_fn)(const float *, const float *, size_t);

static double time_add(add_fn f, float *acc, const float *rows, size_t n_rows, size_t d, const uint32_t *order, size_t reps) {
    double best = 1e30;
    for (int round = 0; round < 5; round++) {
        const double t0 = now();
        for (size_t r = 0; r < reps; r++) {
            f(acc, rows + (size_t) order[r % n_rows] * d, d);
        }
        const double s = now() - t0;
        best = s < best ? s : best;
    }
    return best / (double) reps;
}

static double time_dot(dot_fn f, const float *a, const float *b, size_t d, size_t reps, float *sink) {
    double best = 1e30;
    for (int round = 0; round < 5; round++) {
        const double t0 = now();
        float s = 0.0f;
        for (size_t r = 0; r < reps; r++) {
            s += f(a, b, d);
        }
        *sink += s;
        const double t = now() - t0;
        best = t < best ? t : best;
    }
    return best / (double) reps;
}

int main(int argc, char **argv) {
    enum { MAXN = 2100 };
    static float a[MAXN], b[MAXN], x[MAXN], y[MAXN];
    int    fails = 0;
    double worst_dot = 0.0;
    for (size_t n = 0; n <= MAXN; n += n < 70 ? 1 : 29) {
        for (size_t i = 0; i < n; i++) {
            a[i] = rnd();
            b[i] = rnd() * 40.0f;
            x[i] = y[i] = rnd();
        }
        xv_add(x, b, n);
        xv_add_scalar(y, b, n);
        if (memcmp(x, y, n * sizeof *x) != 0) {
            printf("FAIL  add differs from the scalar form at n = %zu\n", n);
            fails++;
        }
        const double got = (double) xv_dot(a, b, n), want = (double) xv_dot_scalar(a, b, n);
        double mag = 0.0;
        for (size_t i = 0; i < n; i++) {
            mag += fabs((double) a[i] * (double) b[i]);
        }
        const double rel = mag > 0.0 ? fabs(got - want) / mag : fabs(got - want);
        worst_dot = rel > worst_dot ? rel : worst_dot;
        if (rel > 1e-5) {
            printf("FAIL  dot differs from the scalar form at n = %zu: %.9g against %.9g\n", n, got, want);
            fails++;
        }
    }
    printf("%s  kernel %s: add bit-identical to scalar, dot worst relative difference %.3e\n", fails ? "FAIL" : "ok  ", xv_kernel(), worst_dot);
    if (argc < 2 || strcmp(argv[1], "bench") != 0) {
        return fails != 0;
    }

    const size_t d = 2048;
    float *acc = aligned_alloc(64, d * sizeof(float)), *w = aligned_alloc(64, d * sizeof(float));
    float *small = aligned_alloc(64, 16 * d * sizeof(float));
    uint32_t *order = malloc(65536 * sizeof *order);
    for (size_t i = 0; i < d; i++) {
        acc[i] = 0.0f;
        w[i]   = rnd();
    }
    for (size_t i = 0; i < 16 * d; i++) {
        small[i] = rnd();
    }
    for (size_t i = 0; i < 65536; i++) {
        order[i] = (uint32_t) (i % 16);
    }
    float sink = 0.0f;
    const double as = time_add(xv_add_scalar, acc, small, 16, d, order, 200000), av = time_add(xv_add, acc, small, 16, d, order, 200000);
    const double ds = time_dot(xv_dot_scalar, w, small, d, 200000, &sink), dv = time_dot(xv_dot, w, small, d, 200000, &sink);
    printf("add, 2048 floats, 16 rows in cache:   scalar %7.1f ns   %s %7.1f ns   %.2fx\n", as * 1e9, xv_kernel(), av * 1e9, as / av);
    printf("dot, 2048 floats, in cache:           scalar %7.1f ns   %s %7.1f ns   %.2fx\n", ds * 1e9, xv_kernel(), dv * 1e9, ds / dv);

    xv_table t;
    if (argc > 2 && xv_open(&t, argv[2], (int32_t) d) == 0) {
        for (size_t i = 0; i < 65536; i++) {
            g_seed ^= g_seed << 13;
            g_seed ^= g_seed >> 7;
            g_seed ^= g_seed << 17;
            order[i] = (uint32_t) (g_seed % (uint64_t) t.n);
        }
        // one untimed pass brings the rows into the page cache
        time_add(xv_add_scalar, acc, t.rows, 65536, d, order, 65536);
        const double ts = time_add(xv_add_scalar, acc, t.rows, 65536, d, order, 65536), tv = time_add(xv_add, acc, t.rows, 65536, d, order, 65536);
        printf("add, 65536 random rows of the table:  scalar %7.1f ns   %s %7.1f ns   %.2fx   (%.2f GB/s)\n", ts * 1e9, xv_kernel(), tv * 1e9, ts / tv,
               (double) (d * sizeof(float)) / tv / 1e9);
        xv_close(&t);
    }
    printf("(sink %g)\n", (double) sink);
    return fails != 0;
}

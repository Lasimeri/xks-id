#include "cal.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

void xc_reset(xc_cal *c) {
    c->n    = 0;
    c->next = 0;
}

// first slot of sorted[0, n) whose value is not below v
static size_t lower(const float *sorted, size_t n, float v) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (sorted[mid] < v) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

void xc_add(xc_cal *c, float v) {
    if (!isfinite(v)) {
        return;
    }
    if (c->n == XC_WINDOW) {
        // The oldest value leaves. It is in sorted, so the first slot not below it holds it.
        const size_t at = lower(c->sorted, c->n, c->ring[c->next]);
        memmove(c->sorted + at, c->sorted + at + 1, (c->n - at - 1) * sizeof c->sorted[0]);
        c->n--;
    }
    const size_t at = lower(c->sorted, c->n, v);
    memmove(c->sorted + at + 1, c->sorted + at, (c->n - at) * sizeof c->sorted[0]);
    c->sorted[at] = v;
    c->n++;
    c->ring[c->next] = v;
    c->next          = (c->next + 1) % XC_WINDOW;
}

int xc_levels(const xc_cal *c, double *cut, double *lean) {
    if (c->n < XC_MIN) {
        return 0;
    }
    // The value at rank n/1000 from the top, plus a hair: that value itself stays below the cut.
    *cut  = (double) c->sorted[c->n - 1 - c->n / 1000] + 1e-6;
    *lean = (double) c->sorted[c->n - 1 - c->n / 50] + 1e-6;
    return 1;
}

int xc_load(xc_cal *c, const char *path) {
    xc_reset(c);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }
    int ok = fseek(f, 0, SEEK_END) == 0;
    const long size  = ok ? ftell(f) : -1;
    const long total = size > 0 ? size / (long) sizeof(float) : 0;
    const long first = total > XC_WINDOW ? total - XC_WINDOW : 0;
    ok = ok && size >= 0 && fseek(f, first * (long) sizeof(float), SEEK_SET) == 0;
    for (long i = first; ok && i < total; i++) {
        float v;
        ok = fread(&v, sizeof v, 1, f) == 1;
        if (ok) {
            xc_add(c, v);
        }
    }
    fclose(f);
    return ok ? 0 : -1;
}

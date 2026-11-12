// cal_test: the sliding window of cal.c against a plain reference.
//
// Built with a window of 2,500 so that it wraps several times. After every arrival the
// levels are compared with those of a sorted copy of the last 2,500 values of the history.
// The values are coarse on purpose: equal values are the case a removal can get wrong.

#include "../src/xksid/cal.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { STEPS = 12000 };

static uint64_t g_rng = 0x9e3779b97f4a7c15u;

static uint32_t next_u32(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t) (g_rng >> 32);
}

static int by_value(const void *a, const void *b) {
    const float x = *(const float *) a, y = *(const float *) b;
    return (x > y) - (x < y);
}

static int fail(const char *what, int step) {
    fprintf(stderr, "cal_test: %s at step %d\n", what, step);
    return 1;
}

int main(int argc, char **argv) {
    const char *scratch = argc > 1 ? argv[1] : "cal_test.f32";
    static xc_cal live, loaded;
    static float  history[STEPS], copy[XC_WINDOW];

    xc_reset(&live);
    for (int i = 0; i < STEPS; i++) {
        // 401 distinct values between -10 and 10: many ties
        const float v = (float) (next_u32() % 401) * 0.05f - 10.0f;
        history[i]    = v;
        xc_add(&live, v);

        const size_t n = (size_t) i + 1 < XC_WINDOW ? (size_t) i + 1 : XC_WINDOW;
        memcpy(copy, history + i + 1 - n, n * sizeof copy[0]);
        qsort(copy, n, sizeof copy[0], by_value);
        if (live.n != n) {
            return fail("wrong count", i);
        }
        if (memcmp(copy, live.sorted, n * sizeof copy[0]) != 0) {
            return fail("sorted values differ from the reference", i);
        }
        double       cut = 0, lean = 0;
        const int    have = xc_levels(&live, &cut, &lean);
        if (have != (n >= XC_MIN)) {
            return fail("levels given with too few values, or withheld with enough", i);
        }
        if (have && (cut != (double) copy[n - 1 - n / 1000] + 1e-6 || lean != (double) copy[n - 1 - n / 50] + 1e-6)) {
            return fail("levels differ from the reference", i);
        }
    }

    // a non-finite value changes nothing
    const size_t before = live.n;
    xc_add(&live, NAN);
    xc_add(&live, INFINITY);
    if (live.n != before || memcmp(copy, live.sorted, before * sizeof copy[0]) != 0) {
        return fail("a non-finite value was taken", STEPS);
    }

    // a file holding the whole history loads to the same window
    FILE *f = fopen(scratch, "wb");
    if (f == NULL || fwrite(history, sizeof history[0], STEPS, f) != STEPS || fclose(f) != 0) {
        return fail("cannot write the scratch file", STEPS);
    }
    if (xc_load(&loaded, scratch) != 0 || loaded.n != live.n || memcmp(loaded.sorted, live.sorted, live.n * sizeof live.sorted[0]) != 0) {
        return fail("the loaded window differs from the live one", STEPS);
    }
    remove(scratch);
    if (xc_load(&loaded, scratch) != 0 || loaded.n != 0) {
        return fail("a missing file is not an empty window", STEPS);
    }

    printf("cal_test: %d arrivals through a window of %d, levels equal to the reference at every step\n", STEPS, XC_WINDOW);
    return 0;
}

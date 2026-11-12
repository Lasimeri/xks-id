// cal: the alert cut of the decision vectors, kept current from the scored turns themselves.
//
// The engine adds the highest window logit of every scored turn of tool output as it reads
// it. The cut is a quantile of the most recent XC_WINDOW of those values, so it follows the
// operator's own work without a command. A turn is judged first and added after: its own
// logit never takes part in its own verdict.

#ifndef XKSID_CAL_H
#define XKSID_CAL_H

#include <stddef.h>

#ifndef XC_WINDOW
#define XC_WINDOW 8192 // scored turns the levels are taken from
#endif
#ifndef XC_MIN
#define XC_MIN 100 // fewer values than this give no levels
#endif

typedef struct {
    float  ring[XC_WINDOW];   // the values in arrival order; the oldest is at next once the ring is full
    float  sorted[XC_WINDOW]; // the same values, ascending
    size_t n, next;           // values held; slot the next arrival is written to
} xc_cal;

void xc_reset(xc_cal *c);
void xc_add(xc_cal *c, float v); // the oldest value leaves when the window is full; a non-finite value is ignored

// cut: 1 value in 1,000 of the window lies at or above it; lean: 1 in 50.
// Returns 0 and leaves both untouched while the window holds fewer than XC_MIN values.
int xc_levels(const xc_cal *c, double *cut, double *lean);

// Fills the window with the last XC_WINDOW floats of a file, in file order.
// A missing file gives an empty window. Returns -1 on a read error.
int xc_load(xc_cal *c, const char *path);

#endif

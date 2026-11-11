#ifndef XKSID_RULES_H
#define XKSID_RULES_H

#include <stddef.h>
#include <stdint.h>

// One detection rule. The id is what an alert carries; the text explains it to the operator.
typedef struct {
    const char *id;
    int         weight;
    const char *text;
} xr_rule;

extern const xr_rule xr_rules[];
extern const int     xr_n_rules;

enum { XR_I001 = 16, XR_V601 = 17, XR_V602 = 18 }; // rules fired by the reader, not by xr_scan

// How much a turn is trusted decides which rules read it.
enum {
    XR_UNTRUSTED = 1, // tool_result, note: every rule
    XR_OPERATOR  = 2, // user: hidden-character rules only, the operator may word instructions freely
};

typedef struct {
    int      score;  // sum of the weights of the rules that fired, each counted once
    uint32_t fired;  // bit i set: xr_rules[i] fired
    int32_t  offset; // byte offset of the earliest hit in the text, -1 if none
} xr_result;

void xr_fire(xr_result *r, int rule, int32_t offset);
void xr_scan(const unsigned char *text, size_t len, int kind, xr_result *out);

#endif

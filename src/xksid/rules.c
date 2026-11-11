// Content sensors that need no model. Each one answers a documented way of
// injecting instructions into text an agent reads (see docs/METHODS.md):
//   hidden characters      tag block, zero-width bit streams, bidirectional
//                          controls, variation selectors, look-alike letters
//   forged structure       harness tags, chat-template tokens, role headers,
//                          tool-call and role markup, hidden-render markup
//   instruction wording    override, authority, concealment, priority framing,
//                          credential paths, persistence, completion framing,
//                          judged by co-occurrence, never by a single phrase
//   sinks                  image links that carry data, downloads piped to a shell
//   encodings              base64, hexadecimal, binary digits, ROT13 and hidden
//                          characters, decoded and read once more
// Deterministic: the same text gives the same result, and nothing in the text
// can change how it is read.

#include "rules.h"

#include <stdlib.h>
#include <string.h>

enum {
    U101, U102, U103, U104, S201, S202, S203, S204, X301, X302, X303, X304, X305, K501, K502, D001,
    I001, V601, V602, U105, U106, S205, X306, X307, X308, X309, X310, D002, D003, D004,
};

const xr_rule xr_rules[] = {
    [U101] = {"U101", 8, "Unicode tag characters: text that no renderer shows"},
    [U102] = {"U102", 3, "bidirectional control characters"},
    [U103] = {"U103", 3, "zero-width characters inside words"},
    [U104] = {"U104", 6, "run of variation selectors, a carrier for hidden bytes"},
    [U105] = {"U105", 3, "letters of two scripts inside one word: look-alike letters"},
    [U106] = {"U106", 6, "run of zero-width characters, a carrier for hidden bits"},
    [S201] = {"S201", 2, "harness reminder tag inside recorded text"},
    [S202] = {"S202", 3, "chat-template control token inside recorded text"},
    [S203] = {"S203", 2, "line that imitates a system or assistant role header"},
    [S204] = {"S204", 3, "hidden-render markup together with instruction wording"},
    [S205] = {"S205", 3, "tool-call or role markup inside recorded text: imitates the conversation"},
    [X301] = {"X301", 6, "override verb next to an instruction target"},
    [X302] = {"X302", 3, "text addresses an AI with an override or an urgent order"},
    [X303] = {"X303", 6, "tells the reader to hide something from the user"},
    [X304] = {"X304", 5, "authority claim next to an instruction target or an AI addressee"},
    [X305] = {"X305", 6, "text addresses an AI together with a secret or an upload"},
    [X306] = {"X306", 6, "priority framing next to a secret, an upload or a concealment order"},
    [X307] = {"X307", 6, "stacked priority framing: four urgent-order phrases together"},
    [X308] = {"X308", 5, "credential file named next to an AI addressee or a concealment order"},
    [X309] = {"X309", 6, "tells the reader to keep an instruction for later sessions"},
    [X310] = {"X310", 4, "declares the task finished and starts a new one"},
    [K501] = {"K501", 2, "image link whose URL carries a query string"},
    [K502] = {"K502", 1, "download piped into a shell"},
    [D001] = {"D001", 8, "base64 text that decodes to instruction wording"},
    [D002] = {"D002", 8, "hidden characters that decode to instruction wording"},
    [D003] = {"D003", 8, "hexadecimal or binary text that decodes to instruction wording"},
    [D004] = {"D004", 8, "ROT13 text that decodes to instruction wording"},
    [I001] = {"I001", 9, "turn file content does not match the hash in its name"},
    [V601] = {"V601", 3, "decision vectors: a window leans toward instructions aimed at an AI"},
    [V602] = {"V602", 6, "decision vectors: a window scores above the alert cut"},
};
const int xr_n_rules = (int) (sizeof xr_rules / sizeof xr_rules[0]);

_Static_assert((int) I001 == (int) XR_I001 && (int) V601 == (int) XR_V601 && (int) V602 == (int) XR_V602,
               "the reader fires the hash rule and the vector rules by these indexes");
_Static_assert(sizeof xr_rules / sizeof xr_rules[0] <= 32, "a rule is one bit of xr_result.fired");

enum { DECODED_ALERT = 5 }; // wording score at which decoded text counts as instructions

void xr_fire(xr_result *r, int rule, int32_t offset) {
    if (!(r->fired & (1u << rule))) {
        r->fired |= 1u << rule;
        r->score += xr_rules[rule].weight;
    }
    if (offset >= 0 && (r->offset < 0 || offset < r->offset)) {
        r->offset = offset;
    }
}

// one UTF-8 code point; a malformed byte is returned as itself with length 1
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
    *cp = v;
    return n;
}

static int is_zero_width(uint32_t cp) {
    return cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0x2060 || cp == 0xFEFF;
}

static int is_tag(uint32_t cp) {
    return cp >= 0xE0000 && cp <= 0xE007F;
}

static int is_invisible(uint32_t cp) {
    return is_zero_width(cp) || is_tag(cp) || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) ||
           (cp >= 0xE0100 && cp <= 0xE01EF);
}

static int is_alnum(uint32_t cp) {
    return (cp >= '0' && cp <= '9') || (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z');
}

static int is_letter(uint32_t cp) {
    return (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z');
}

static int is_other_script(uint32_t cp) { // Greek and Cyrillic letters
    return (cp >= 0x0370 && cp <= 0x03FF) || (cp >= 0x0400 && cp <= 0x052F);
}

// Letters of other scripts that are drawn like a Latin letter, and full-width forms.
// Returns the lower-case Latin letter, or 0 when the code point has no look-alike.
static char look_alike(uint32_t cp) {
    static const struct {
        uint16_t cp;
        char     latin;
    } MAP[] = {
        {0x0430, 'a'}, {0x0435, 'e'}, {0x043E, 'o'}, {0x0440, 'p'}, {0x0441, 'c'}, {0x0443, 'y'}, {0x0445, 'x'}, {0x0455, 's'},
        {0x0456, 'i'}, {0x0458, 'j'}, {0x04BB, 'h'}, {0x0501, 'd'}, {0x051B, 'q'}, {0x051D, 'w'}, {0x0410, 'a'}, {0x0412, 'b'},
        {0x0415, 'e'}, {0x041A, 'k'}, {0x041C, 'm'}, {0x041D, 'h'}, {0x041E, 'o'}, {0x0420, 'p'}, {0x0421, 'c'}, {0x0422, 't'},
        {0x0425, 'x'}, {0x0405, 's'}, {0x0406, 'i'}, {0x0408, 'j'}, {0x03BF, 'o'}, {0x03B1, 'a'}, {0x03BD, 'v'}, {0x03C1, 'p'},
        {0x03B9, 'i'}, {0x03BA, 'k'}, {0x03C5, 'u'}, {0x0391, 'a'}, {0x0392, 'b'}, {0x0395, 'e'}, {0x0396, 'z'}, {0x0397, 'h'},
        {0x0399, 'i'}, {0x039A, 'k'}, {0x039C, 'm'}, {0x039D, 'n'}, {0x039F, 'o'}, {0x03A1, 'p'}, {0x03A4, 't'}, {0x03A5, 'y'},
        {0x03A7, 'x'},
    };
    if (cp >= 0xFF21 && cp <= 0xFF3A) {
        return (char) (cp - 0xFF21 + 'a');
    }
    if (cp >= 0xFF41 && cp <= 0xFF5A) {
        return (char) (cp - 0xFF41 + 'a');
    }
    for (size_t i = 0; i < sizeof MAP / sizeof MAP[0]; i++) {
        if (MAP[i].cp == cp) {
            return MAP[i].latin;
        }
    }
    return 0;
}

static void lexical(const unsigned char *t, size_t len, int depth, xr_result *r);

// decoded text that reads like instructions fires the rule of its encoding
static void judge_decoded(const unsigned char *text, size_t len, int rule, int32_t at, xr_result *r) {
    if (len < 12) {
        return;
    }
    size_t printable = 0;
    for (size_t i = 0; i < len; i++) {
        printable += (size_t) ((text[i] >= 0x20 && text[i] < 0x7F) || text[i] == '\n' || text[i] == '\t');
    }
    if (printable * 10 < len * 9) {
        return;
    }
    xr_result inner = {0, 0, -1};
    lexical(text, len, 1, &inner);
    if (inner.score >= DECODED_ALERT) {
        xr_fire(r, rule, at);
    }
}

// Hidden characters. Tag characters after a black flag are a flag emoji and are left alone.
// Other tag characters spell ASCII; zero-width space and non-joiner spell bits. Both are
// collected and read as text.
static void unicode_pass(const unsigned char *t, size_t len, xr_result *r) {
    enum { CAP = 8192 };
    unsigned char *tags = malloc(CAP), *bits = malloc(CAP);
    size_t  n_tags = 0, n_bits = 0, bit_count = 0;
    int     zw = 0, vs_run = 0, zw_run = 0, prev_alnum = 0, pending = 0, in_flag = 0, mixed = 0;
    int     word_latin = 0, word_other = 0;
    int32_t zw_at = -1, vs_at = 0, pending_at = 0, tag_at = -1, run_at = 0, mixed_at = -1, word_at = 0;
    unsigned acc = 0;
    for (size_t i = 0; tags != NULL && bits != NULL && i < len;) {
        uint32_t      cp;
        const size_t  n  = decode(t + i, len - i, &cp);
        const int32_t at = (int32_t) i;
        if (cp == 0x1F3F4) {
            in_flag = 1;
        } else if (is_tag(cp)) {
            if (!in_flag) {
                if (n_tags == 0) {
                    tag_at = at;
                }
                if (n_tags < CAP && cp >= 0xE0020 && cp <= 0xE007E) {
                    tags[n_tags++] = (unsigned char) (cp - 0xE0000);
                }
            } else if (cp == 0xE007F) {
                in_flag = 0;
            }
        } else {
            in_flag = 0;
        }
        if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) {
            xr_fire(r, U102, at);
        }
        if (cp >= 0xE0100 && cp <= 0xE01EF) {
            if (vs_run++ == 0) {
                vs_at = at;
            }
            if (vs_run == 4) {
                xr_fire(r, U104, vs_at);
            }
        } else {
            vs_run = 0;
        }
        if (is_zero_width(cp) && i > 0) {
            if (zw_run++ == 0) {
                run_at = at;
            }
            if (zw_run == 16) {
                xr_fire(r, U106, run_at);
            }
            if (cp == 0x200B || cp == 0x200C) {
                acc = acc << 1 | (cp == 0x200C);
                if (++bit_count % 8 == 0 && n_bits < CAP) {
                    bits[n_bits++] = (unsigned char) acc;
                }
            }
            if (prev_alnum) {
                pending    = 1;
                pending_at = at;
            }
        } else {
            zw_run = 0;
            if (pending && is_alnum(cp) && zw++ == 0) {
                zw_at = pending_at;
            }
            pending    = 0;
            prev_alnum = is_alnum(cp);
            // a word that mixes Latin letters with Greek or Cyrillic ones
            if (is_letter(cp) || is_other_script(cp)) {
                if (!word_latin && !word_other) {
                    word_at = at;
                }
                word_latin |= is_letter(cp);
                word_other |= is_other_script(cp);
            } else {
                if (word_latin && word_other && mixed++ == 0) {
                    mixed_at = word_at;
                }
                word_latin = word_other = 0;
            }
        }
        i += n;
    }
    if (word_latin && word_other && mixed++ == 0) {
        mixed_at = word_at;
    }
    if (zw >= 3) {
        xr_fire(r, U103, zw_at);
    }
    if (mixed >= 2) {
        xr_fire(r, U105, mixed_at);
    }
    if (n_tags >= 4) {
        xr_fire(r, U101, tag_at);
        judge_decoded(tags, n_tags, D002, tag_at, r);
    }
    if (tags != NULL && bits != NULL) {
        judge_decoded(bits, n_bits, D002, run_at, r);
    }
    free(tags);
    free(bits);
}

// Lower case, one space per whitespace run, invisible characters removed, look-alike
// letters written as Latin, curly apostrophes straightened. off[i] is the offset in the
// text of normalised byte i.
static size_t normalise(const unsigned char *t, size_t len, char *out, int32_t *off) {
    size_t m = 0;
    int    space = 1;
    for (size_t i = 0; i < len;) {
        uint32_t     cp;
        const size_t n = decode(t + i, len - i, &cp);
        if (is_invisible(cp)) {
            i += n;
            continue;
        }
        if (cp == 0x2018 || cp == 0x2019) {
            cp = '\'';
        } else if (cp >= 0x80 && look_alike(cp)) {
            cp = (uint32_t) (unsigned char) look_alike(cp);
        }
        if (cp < 0x80) {
            const char c = (char) cp;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0) {
                if (!space) {
                    out[m] = ' ';
                    off[m++] = (int32_t) i;
                }
                space = 1;
            } else {
                out[m] = (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
                off[m++] = (int32_t) i;
                space = 0;
            }
        } else {
            for (size_t j = 0; j < n; j++) {
                out[m] = (char) t[i + j];
                off[m++] = (int32_t) (i + j);
            }
            space = 0;
        }
        i += n;
    }
    out[m] = 0;
    return m;
}

// positions of the phrases of one class in the normalised text, and which phrase each is
typedef struct {
    int32_t pos[48];
    int16_t which[48];
    int     n;
} hits;

static int word_start(const char *text, const char *p) {
    if (p == text) {
        return 1;
    }
    const unsigned char c = (unsigned char) p[-1];
    return !(is_alnum(c) || c == '_' || c == '.' || c == '/' || c == '-');
}

// boundary: a hit must start a word. Paths and markup are matched anywhere.
static void find(const char *text, const char *const *phrases, int boundary, hits *h) {
    h->n = 0;
    for (int16_t k = 0; phrases[k] != NULL; k++) {
        const size_t n = strlen(phrases[k]);
        for (const char *p = text; (p = strstr(p, phrases[k])) != NULL && h->n < 48; p += n) {
            if (!boundary || word_start(text, p)) {
                h->pos[h->n]     = (int32_t) (p - text);
                h->which[h->n++] = k;
            }
        }
    }
}

// earliest position of a hit of a that has a hit of b within width bytes, or -1
static int32_t near(const hits *a, const hits *b, int32_t width) {
    int32_t best = -1;
    for (int i = 0; i < a->n; i++) {
        for (int j = 0; j < b->n; j++) {
            const int32_t d = a->pos[i] - b->pos[j];
            if (d <= width && d >= -width) {
                const int32_t at = a->pos[i] < b->pos[j] ? a->pos[i] : b->pos[j];
                if (best < 0 || at < best) {
                    best = at;
                }
            }
        }
    }
    return best;
}

// position of a hit with four different phrases of its class within width bytes after it, or -1
static int32_t stacked(const hits *a, int32_t width) {
    for (int i = 0; i < a->n; i++) {
        int16_t seen[48];
        int     n_seen = 0;
        for (int j = 0; j < a->n; j++) {
            const int32_t d = a->pos[j] - a->pos[i];
            if (d < 0 || d > width) {
                continue;
            }
            int known = 0;
            for (int k = 0; k < n_seen; k++) {
                known |= seen[k] == a->which[j];
            }
            if (!known) {
                seen[n_seen++] = a->which[j];
            }
        }
        if (n_seen >= 4) {
            return a->pos[i];
        }
    }
    return -1;
}

static int32_t first(const hits *h) {
    int32_t best = -1;
    for (int i = 0; i < h->n; i++) {
        if (best < 0 || h->pos[i] < best) {
            best = h->pos[i];
        }
    }
    return best;
}

static const char *const OVERRIDE[] = {
    "ignore all", "ignore the", "ignore any", "ignore previous", "ignore prior", "ignore your", "ignore above",
    "ignore every", "disregard", "forget all", "forget your", "forget everything", "forget previous",
    "forget the above", "override your", "override the", "do not follow", "don't follow", "stop following",
    "no longer follow", "replace your", "set aside your", NULL};
static const char *const TARGET[] = {
    "previous instructions", "prior instructions", "earlier instructions", "above instructions",
    "preceding instructions", "all instructions", "your instructions", "instructions above", "system prompt",
    "system instructions", "previous prompt", "your rules", "your guidelines", "prior directives",
    "previous directions", "earlier guidance", NULL};
static const char *const ADDRESSEE[] = {
    "ai assistant", "ai agent", "ai model", "language model", "you are now", "as an ai", "dear ai",
    "attention ai", "dear assistant", "attention assistant", "to the assistant", "the assistant must",
    "the assistant should", "assistant reading", "agent reading", "ai reading", "llm reading",
    "if you are an ai", "if you are a language", "note to ai", "note to the ai", "note for ai",
    "automated assistant", "automated reader", "to the agent", "the agent must", "the agent should", NULL};
static const char *const SECRECY[] = {
    "do not tell the user", "don't tell the user", "never tell the user", "do not inform the user",
    "don't inform the user", "without telling the user", "without informing the user", "hide this from the user",
    "keep this secret from", "the user should not know", "the user must not know", "do not let the user",
    "don't let the user", "without the user's knowledge", "do not mention this to the user", NULL};
static const char *const QUIET[] = { // concealment that does not name the user: counts in combination only
    "do not mention", "don't mention", "without mentioning", "do not tell anyone", "do not reveal this",
    "do not disclose this", "do not show this", "say nothing about", "without notifying", NULL};
static const char *const AUTHORITY[] = {
    "system notice", "system override", "system message:", "new instructions", "updated instructions",
    "important instruction", "admin override", "administrator override", "developer mode",
    "the user has authorized", "the user has authorised", "official instruction", "priority instruction",
    "instructions are replaced", "instructions have changed", "you must now", "from now on you", NULL};
static const char *const EXFIL[] = {
    "send the contents", "send the content", "send all", "upload the", "exfiltrate", "api key", "api keys",
    "private key", "ssh key", "password", "credentials", "environment file", "environment variables",
    "access token", "secret key", "pass its content", "include its content", "paste it into", NULL};
static const char *const PRIORITY[] = {
    "important:", "important!", "<important>", "<information>", "very important", "important message from",
    "this is an important message", "before using this tool", "before calling", "before you can",
    "before returning", "before answering", "before responding", "before you continue", "before proceeding",
    "do the following first", "you must first", "first, you must", "strictly adhere", "strictly follow",
    "it is required that you", "otherwise the tool will not work", "mandatory step", NULL};
static const char *const SECRETPATH[] = {
    "~/.ssh", ".ssh/id_", "id_rsa", "id_ed25519", ".aws/credentials", "mcp.json", "authorized_keys", ".netrc",
    ".npmrc", ".git-credentials", "/etc/passwd", "/etc/shadow", "wallet.dat", NULL};
static const char *const PERSIST[] = {
    "in all future conversations", "in every future", "for all future", "in future sessions",
    "remember this for", "store this in your memory", "save this to your memory", "add this to your memory",
    "update your memory", "permanently remember", "store this instruction", NULL};
static const char *const COMPLETION[] = {
    "task is complete", "task completed", "task is now complete", "new task:", "your next task", "your new task",
    "next instruction:", "new instruction:", "now do the following", "the actual task", "the real task", NULL};
static const char *const REMINDER[] = {"<system-reminder>", "</system-reminder>", NULL};
static const char *const TEMPLATE[] = {
    "<|im_start|>", "<|im_end|>", "[inst]", "<<sys>>", "<|start_header_id|>", "<|eot_id|>", "<|endoftext|>",
    "<|assistant|>", "<|system|>", "<|user|>", NULL};
static const char *const STRUCTURE[] = {
    "<tool_call>", "</tool_call>", "<tool_response>", "</tool_response>", "<function=", "<function_calls>",
    "\"role\": \"system\"", "\"role\":\"system\"", "\"role\": \"assistant\"", "\"role\":\"assistant\"", NULL};
static const char *const HIDDEN[] = {
    "display:none", "display: none", "font-size:0", "font-size: 0", "visibility:hidden", "visibility: hidden", NULL};
static const char *const ROLE_LINE[] = {
    "system:", "system notice", "system message", "[system]", "assistant:", "human:", NULL};

// a role header counts only at the start of a line, after quote and list marks
static void role_lines(const unsigned char *t, size_t len, xr_result *r) {
    for (size_t i = 0; i < len;) {
        size_t s = i;
        while (s < len && (t[s] == ' ' || t[s] == '\t' || t[s] == '>' || t[s] == '*' || t[s] == '#' || t[s] == '-')) {
            s++;
        }
        for (const char *const *p = ROLE_LINE; *p != NULL; p++) {
            const size_t n = strlen(*p);
            size_t       k = 0;
            while (k < n && s + k < len) {
                const unsigned char c = t[s + k];
                if ((char) ((c >= 'A' && c <= 'Z') ? c + 32 : c) != (*p)[k]) {
                    break;
                }
                k++;
            }
            if (k == n) {
                xr_fire(r, S203, (int32_t) s);
            }
        }
        while (i < len && t[i] != '\n') {
            i++;
        }
        i++;
    }
}

static int b64_value(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' ? 62 : c == '/' ? 63 : -1;
}

static int hex_value(unsigned char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

// Runs of base64 (48 to 8192 characters), of hexadecimal digits (48 or more) and of
// 8-digit binary groups (12 or more) are decoded and read as text. At most 16 runs of
// each kind per turn.
static void encoded_pass(const unsigned char *t, size_t len, xr_result *r) {
    unsigned char *dec = malloc(len + 16); // no decoding here yields more bytes than it reads
    if (dec == NULL) {
        return;
    }
    int n_b64 = 0, n_hex = 0, n_bin = 0;
    for (size_t i = 0; i < len;) {
        size_t j = i;
        while (j < len && b64_value(t[j]) >= 0) {
            j++;
        }
        const size_t run = j - i;
        size_t       h   = i;
        while (h < j && hex_value(t[h]) >= 0) {
            h++;
        }
        if (h == j && run >= 48 && run % 2 == 0 && n_hex < 16) {
            n_hex++;
            for (size_t k = 0; k < run / 2; k++) {
                dec[k] = (unsigned char) (hex_value(t[i + 2 * k]) << 4 | hex_value(t[i + 2 * k + 1]));
            }
            judge_decoded(dec, run / 2, D003, (int32_t) i, r);
        }
        if (run >= 48 && run <= 8192 && n_b64 < 16) {
            n_b64++;
            size_t   m = 0;
            uint32_t acc = 0;
            int      bits = 0;
            for (size_t k = i; k < j; k++) {
                acc = acc << 6 | (uint32_t) b64_value(t[k]);
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    dec[m++] = (unsigned char) (acc >> bits);
                }
            }
            judge_decoded(dec, m, D001, (int32_t) i, r);
        }
        // binary: groups of exactly eight 0 or 1, separated by single spaces
        if (run == 8 && n_bin < 16) {
            size_t m = 0, k = i;
            while (k + 8 <= len) {
                unsigned v = 0;
                size_t   b = 0;
                while (b < 8 && (t[k + b] == '0' || t[k + b] == '1')) {
                    v = v << 1 | (unsigned) (t[k + b] - '0');
                    b++;
                }
                if (b != 8 || (k + 8 < len && b64_value(t[k + 8]) >= 0)) {
                    break;
                }
                dec[m++] = (unsigned char) v;
                k += 8;
                if (k < len && t[k] == ' ') {
                    k++;
                }
            }
            if (m >= 12) {
                n_bin++;
                judge_decoded(dec, m, D003, (int32_t) i, r);
                j = k;
            }
        }
        i = j + 1;
    }
    free(dec);
}

static void rot13_pass(const unsigned char *t, size_t len, xr_result *r) {
    unsigned char *rot = malloc(len + 1);
    if (rot == NULL) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = t[i];
        rot[i] = c >= 'a' && c <= 'z' ? (unsigned char) ('a' + (c - 'a' + 13) % 26)
               : c >= 'A' && c <= 'Z' ? (unsigned char) ('A' + (c - 'A' + 13) % 26) : c;
    }
    xr_result inner = {0, 0, -1};
    lexical(rot, len, 1, &inner);
    if (inner.score >= DECODED_ALERT) {
        xr_fire(r, D004, inner.offset);
    }
    free(rot);
}

// Wording rules on the normalised text. depth 0 is the text of the turn; depth 1 is text
// that was decoded from it, where only the wording is judged.
static void lexical(const unsigned char *t, size_t len, int depth, xr_result *r) {
    char    *text = malloc(len + 1);
    int32_t *off  = malloc((len + 1) * sizeof *off);
    if (text == NULL || off == NULL) {
        free(text);
        free(off);
        return;
    }
    normalise(t, len, text, off);

    hits over, target, addr, secret, quiet, auth, exfil, prio, spath, persist, done;
    find(text, OVERRIDE, 1, &over);
    find(text, TARGET, 1, &target);
    find(text, ADDRESSEE, 1, &addr);
    find(text, SECRECY, 1, &secret);
    find(text, QUIET, 1, &quiet);
    find(text, AUTHORITY, 1, &auth);
    find(text, EXFIL, 1, &exfil);
    find(text, PRIORITY, 0, &prio);
    find(text, SECRETPATH, 0, &spath);
    find(text, PERSIST, 1, &persist);
    find(text, COMPLETION, 1, &done);

    int32_t at;
    if ((at = near(&over, &target, 120)) >= 0) {
        xr_fire(r, X301, off[at]);
    }
    if ((at = near(&addr, &over, 200)) >= 0 || (at = near(&addr, &prio, 200)) >= 0) {
        xr_fire(r, X302, off[at]);
    }
    if ((at = first(&secret)) >= 0) {
        xr_fire(r, X303, off[at]);
    }
    if ((at = near(&auth, &target, 200)) >= 0 || (at = near(&auth, &addr, 200)) >= 0) {
        xr_fire(r, X304, off[at]);
    }
    if ((at = near(&addr, &exfil, 250)) >= 0) {
        xr_fire(r, X305, off[at]);
    }
    if ((at = near(&prio, &exfil, 250)) >= 0 || (at = near(&prio, &spath, 250)) >= 0 || (at = near(&prio, &quiet, 250)) >= 0) {
        xr_fire(r, X306, off[at]);
    }
    if ((at = stacked(&prio, 300)) >= 0) {
        xr_fire(r, X307, off[at]);
    }
    if ((at = near(&spath, &addr, 250)) >= 0 || (at = near(&spath, &quiet, 250)) >= 0 || (at = near(&spath, &secret, 250)) >= 0) {
        xr_fire(r, X308, off[at]);
    }
    if ((at = near(&persist, &addr, 250)) >= 0 || (at = near(&persist, &prio, 250)) >= 0 || (at = near(&persist, &over, 250)) >= 0) {
        xr_fire(r, X309, off[at]);
    }
    if ((at = near(&done, &over, 200)) >= 0 || (at = near(&done, &prio, 200)) >= 0 || (at = near(&done, &addr, 200)) >= 0) {
        xr_fire(r, X310, off[at]);
    }
    if (depth == 0) {
        hits rem, tmpl, structure, hidden;
        find(text, REMINDER, 0, &rem);
        find(text, TEMPLATE, 0, &tmpl);
        find(text, STRUCTURE, 0, &structure);
        find(text, HIDDEN, 0, &hidden);
        if ((at = first(&rem)) >= 0) {
            xr_fire(r, S201, off[at]);
        }
        if ((at = first(&tmpl)) >= 0) {
            xr_fire(r, S202, off[at]);
        }
        if ((at = first(&structure)) >= 0) {
            xr_fire(r, S205, off[at]);
        }
        if ((at = first(&hidden)) >= 0 && over.n + secret.n + auth.n + addr.n + prio.n > 0) {
            xr_fire(r, S204, off[at]);
        }
        // sinks: an image link with a query string, markdown or HTML; a download piped to a shell
        for (const char *p = text; (p = strstr(p, "](http")) != NULL; p++) {
            const char *end = strchr(p, ')');
            const char *q   = strchr(p, '?');
            const char *open = p;
            while (open > text && p - open < 300 && *open != '[') {
                open--;
            }
            if (end != NULL && q != NULL && q < end && end - p < 600 && open > text && open[-1] == '!') {
                xr_fire(r, K501, off[open - 1 - text]);
                break;
            }
        }
        for (const char *p = text; (p = strstr(p, "<img ")) != NULL; p++) {
            const char *end = strchr(p, '>');
            const char *src = strstr(p, "src=");
            const char *q   = strchr(p, '?');
            if (end != NULL && src != NULL && q != NULL && src < q && q < end && strstr(src, "http") == src + 4 + (src[4] == '"' || src[4] == '\'')) {
                xr_fire(r, K501, off[p - text]);
                break;
            }
        }
        for (const char *p = text; (p = strstr(p, "| ")) != NULL; p++) {
            const int shell = strncmp(p + 2, "sh", 2) == 0 || strncmp(p + 2, "bash", 4) == 0 || strncmp(p + 2, "sudo ", 5) == 0;
            if (!shell) {
                continue;
            }
            const char *from = p - text > 200 ? p - 200 : text;
            for (const char *c = from; c < p; c++) {
                if (strncmp(c, "curl ", 5) == 0 || strncmp(c, "wget ", 5) == 0) {
                    xr_fire(r, K502, off[c - text]);
                    break;
                }
            }
        }
    }
    free(text);
    free(off);
}

void xr_scan(const unsigned char *text, size_t len, int kind, xr_result *out) {
    out->score  = 0;
    out->fired  = 0;
    out->offset = -1;
    unicode_pass(text, len, out);
    if (kind != XR_UNTRUSTED) {
        return;
    }
    lexical(text, len, 0, out);
    role_lines(text, len, out);
    encoded_pass(text, len, out);
    rot13_pass(text, len, out);
}

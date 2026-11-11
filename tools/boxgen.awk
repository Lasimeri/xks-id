# boxgen.awk: build the fixed-width box-drawing diagram from docs/diagram.spec.
#
#   LC_ALL=C.UTF-8 awk -f tools/boxgen.awk docs/diagram.spec > docs/diagram.txt
#
# Spec format, one output line per input line, fields separated by '@':
#   TITLE@text                  top border carrying the title
#   src@gap@mode@conn@ledger    five columns of fixed width 24, 18, 32, 4, 18
#   RAW@text@ledger             free text over the first four columns
# An empty field becomes spaces. A non-empty field of the wrong width is an
# error: the script names the line and the field and exits 1, so a diagram
# with a misaligned edge cannot be generated. "{N}" in RAW text is N spaces.
# Every output line is 100 characters wide. Needs a UTF-8 locale.

BEGIN {
    FS = "@"
    W[1] = 24; W[2] = 18; W[3] = 32; W[4] = 4; W[5] = 18
}
function sp(n,   s) { s = ""; while (n-- > 0) s = s " "; return s }
function fail(msg) { print "boxgen: line " NR ": " msg > "/dev/stderr"; bad = 1 }
function expand(s,   n) {
    while (match(s, /\{[0-9]+\}/)) {
        n = substr(s, RSTART + 1, RLENGTH - 2) + 0
        s = substr(s, 1, RSTART - 1) sp(n) substr(s, RSTART + RLENGTH)
    }
    return s
}
$1 == "TITLE" {
    t = "══ " $2 " "
    if (length(t) > 98) fail("title width " length(t))
    while (length(t) < 98) t = t "═"
    print "╔" t "╗"
    next
}
$1 == "RAW" {
    l = expand($2); led = $3; want = (led == "" ? 96 : 78)
    if (length(l) > want) fail("raw width " length(l) ", limit " want)
    if (led != "" && length(led) != 18) fail("ledger width " length(led) ", want 18")
    print "║ " l sp(want - length(l)) led " ║"
    next
}
{
    out = ""
    for (i = 1; i <= 5; i++) {
        f = $i
        if (f == "") f = sp(W[i])
        else if (length(f) != W[i]) fail("field " i " width " length(f) ", want " W[i])
        out = out f
    }
    print "║ " out " ║"
}
END {
    b = ""; while (length(b) < 98) b = b "═"
    print "╚" b "╝"
    exit bad
}

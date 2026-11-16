/*
 * Content half of net/mbuf_pulldown (see there), part 3: the bytes
 * after the range stay at their packet offsets.  Smaller than the other
 * parts for solver time: packets up to 24 bytes, so the new cluster of
 * the last case is not reached here (the other parts reach it).
 */
#define CONTENT	3
#define MAXLEN	24
#include "../mbuf_pulldown/harness.c"

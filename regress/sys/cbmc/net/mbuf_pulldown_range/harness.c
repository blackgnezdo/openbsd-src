/*
 * Content half of net/mbuf_pulldown (see there), part 2: the bytes of
 * [off, off + len) stay at their packet offsets and are at mtod(n) +
 * *offp + k.
 */
#define CONTENT	2
#include "../mbuf_pulldown/harness.c"

/*
 * Content half of net/mbuf_pulldown (see there), part 1: the bytes
 * before off stay where they were.
 */
#define CONTENT	1
#include "../mbuf_pulldown/harness.c"

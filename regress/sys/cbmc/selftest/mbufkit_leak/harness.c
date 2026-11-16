/*
 * A chain the harness drops is a leak: mbufs and clusters come from the
 * heap model, --memory-leak-check reports them.
 */
#define MBUFKIT_MAXLEN	16
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m;

	mbufkit_init();
	m = mbufkit_build(mbufkit_upto(16), MBUFKIT_ANY);
#include <anchor.inc>
	mbufkit_check(m);
	return (0);
}

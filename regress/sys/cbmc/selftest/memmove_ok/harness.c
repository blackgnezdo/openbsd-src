/*
 * memmove through the kernel macro must perform the copy, also for
 * overlapping regions: moving buf[0..5] up by two bytes yields the old
 * content.  Pins down the "memmove had no body" defect.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	unsigned char *buf, old[8];
	int i;

	buf = malloc(8, M_TEMP, M_WAITOK);
	for (i = 0; i < 8; i++)
		old[i] = buf[i];
#include <anchor.inc>
	memmove(buf + 2, buf, 6);
	for (i = 0; i < 6; i++)
		__CPROVER_assert(buf[i + 2] == old[i], "memmove moved byte");
	free(buf, M_TEMP, 8);
	return (0);
}

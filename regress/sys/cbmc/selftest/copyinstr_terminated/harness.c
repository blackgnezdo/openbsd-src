/*
 * copyinstr(9) contract kept by the model: on 0 the buffer holds a NUL
 * at *done - 1 and 1 <= *done <= len; on ENAMETOOLONG *done == len; no
 * other result than 0, EFAULT or ENAMETOOLONG.  Both successful
 * outcomes are anchored.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/malloc.h>

unsigned long nondet_ulong(void);

int
main(void)
{
	char *buf;
	size_t done = 0;
	int error;

	buf = malloc(8, M_TEMP, M_WAITOK);
	error = copyinstr((const void *)nondet_ulong(), buf, 8, &done);
	__CPROVER_assert(error == 0 || error == EFAULT ||
	    error == ENAMETOOLONG, "copyinstr result");
	if (error == 0) {
#include <anchor.inc>
		__CPROVER_assert(done >= 1 && done <= 8, "done within len");
		__CPROVER_assert(buf[done - 1] == '\0', "terminated");
	} else if (error == ENAMETOOLONG) {
#include <anchor2.inc>
		__CPROVER_assert(done == 8, "ENAMETOOLONG fills buffer");
	}
	free(buf, M_TEMP, 8);
	return (0);
}

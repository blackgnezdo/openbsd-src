/*
 * Counterpart of unwind_too_small: --unwind 6 covers five iterations
 * (the check for the exit condition is the sixth).
 */
int
main(void)
{
	volatile int n = 5;
	int i, sum = 0;

#include <anchor.inc>
	for (i = 0; i < n; i++)
		sum += i;
	__CPROVER_assert(sum == 10, "sum");
	return (sum);
}

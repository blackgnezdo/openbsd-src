/*
 * A loop with five iterations and --unwind 3: the unwinding assertion
 * must fail, so that an insufficient bound is never a silent pass.
 */
int
main(void)
{
	volatile int n = 5;
	int i, sum = 0;

#include <anchor.inc>
	for (i = 0; i < n; i++)
		sum += i;
	return (sum);
}

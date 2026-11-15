/*
 * The anchor sits in code the harness makes unreachable (n is never
 * above 1): no failure exists, but the result must be VACUOUS, not
 * VERIFIED.
 */
int
main(void)
{
	unsigned char n = 1;

	if (n > 1) {
#include <anchor.inc>
		__CPROVER_assert(0, "dead code");
	}
	return (0);
}

/*
 * A function listed in keep keeps its body: f() == 7.
 */
int f(void);

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(f() == 7, "f() == 7");
	return (0);
}

/*
 * replace: calls to g in kernel code go to model_g of the harness; h
 * (kept) must see its result and the harness its side effect.
 */
int h(void);

static int ncalls;

int
model_g(void)
{
	ncalls++;
	return 5;
}

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(h() == 105, "h() sees model_g's result");
	__CPROVER_assert(ncalls == 1, "model_g ran once");
	return (0);
}

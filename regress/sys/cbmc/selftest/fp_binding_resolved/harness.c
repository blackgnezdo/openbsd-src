/*
 * Positive direction of fp_binding_with_replace: the table is ops_a,
 * the binding to op_a holds, replace still redirects other().  Result
 * 10 + 1 + 100.
 */
struct ops {
	int (*op)(int);
};
extern struct ops ops_a;
int run_op(struct ops *);

int
model_other(void)
{
	return 100;
}

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(run_op(&ops_a) == 111, "bound op_a and replaced other");
	return (0);
}

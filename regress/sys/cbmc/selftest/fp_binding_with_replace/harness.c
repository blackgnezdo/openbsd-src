/*
 * fptargets binds the call in run_op to op_a while replace redirects
 * other(); both must take effect in one target.  The table is chosen
 * nondeterministically, so the binding (an assertion that the pointer
 * is op_a) must fail on the ops_b path.  Without the binding op_b is a
 * candidate and the failure is the result check instead.
 */
struct ops {
	int (*op)(int);
};
extern struct ops ops_a, ops_b;
int run_op(struct ops *);
_Bool nondet_bool(void);

int
model_other(void)
{
	return 100;
}

int
main(void)
{
	struct ops *o = nondet_bool() ? &ops_a : &ops_b;

#include <anchor.inc>
	__CPROVER_assert(run_op(o) == 111, "bound op_a and replaced other");
	return (0);
}

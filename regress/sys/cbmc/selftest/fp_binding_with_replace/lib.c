/*
 * run_op() calls through a method table.  op_a and op_b have the same
 * type and their addresses are taken, so without a binding CBMC tries
 * both at the call site.  other() has no body and is replaced.
 */
struct ops {
	int (*op)(int);
};

int other(void);

int
op_a(int x)
{
	return x + 1;
}

int
op_b(int x)
{
	return x + 2;
}

struct ops ops_a = { op_a };
struct ops ops_b = { op_b };

int
run_op(struct ops *o)
{
	return o->op(10) + other();
}

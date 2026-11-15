/*
 * "Kernel file" for minmax: calls the libkern inline functions from a
 * kept function, so that their bodies come from a header of a compiled
 * kernel file (not from the harness) and must survive body removal.
 * Arguments are widened so that the callee's parameter types decide.
 */
#include <sys/param.h>
#include <sys/systm.h>

u_long
w_min(u_long a, u_long b)
{
	return min(a, b);
}

u_long
w_max(u_long a, u_long b)
{
	return max(a, b);
}

long
w_imin(long a, long b)
{
	return imin(a, b);
}

long
w_imax(long a, long b)
{
	return imax(a, b);
}

long
w_lmin(long a, long b)
{
	return lmin(a, b);
}

long
w_lmax(long a, long b)
{
	return lmax(a, b);
}

u_long
w_ulmin(u_long a, u_long b)
{
	return ulmin(a, b);
}

u_long
w_ulmax(u_long a, u_long b)
{
	return ulmax(a, b);
}

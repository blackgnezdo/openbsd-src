/*
 * Harness: rtm_setmetrics() and rtm_getmetrics() of sys/net/rtsock.c,
 * the conversion of a route's expiry between userland's wall clock and
 * the kernel's uptime, on an arbitrary rmx_expire (an int64_t of the
 * routing message, nothing checks it: route_output passes rtm_rmx
 * through) and arbitrary clocks: gettime() and getuptime() are any
 * non-negative time_t (models), rt_timer_get_expire any non-negative
 * uptime.
 *
 * opts turns on --signed-overflow-check (cbmc.sh runs without the
 * standard checks): the property is that neither direction overflows.
 * Postconditions, asserted below:
 *  S1  the stored expiry is 0 exactly when userland asked for 0;
 *  S2  otherwise it is positive (an expiry in the past is 1, expired,
 *      not 0, which would mean never);
 *  S3  when userland's expiry is nonzero, after boot and does not
 *      saturate, the stored value is the same instant in uptime;
 *  R   with the clocks unchanged, reading back a stored expiry that
 *      did not saturate gives userland's value.
 *
 * mutant_prefix/ is the source before the conversions saturated:
 * VIOLATED on signed overflow, and on S2 (an expiry at boot was stored
 * as 0, never).  mutant_set/ and mutant_get/ revert one direction each.
 */
#define INET6	1
#include "rtsock.c"
#include "cbmc_harness.h"

/* CBMC's free for objects of CBMC_NEW (kernel free(9) is kfree here) */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

int64_t g_time, g_uptime;

time_t
model_gettime(void)
{
	return (g_time);
}

time_t
model_getuptime(void)
{
	return (g_uptime);
}

time_t
model_rt_timer_get_expire(const struct rtentry *rt)
{
	int64_t v = nondet_long();

	return (v < 0 ? 0 : v);
}

int
main(void)
{
	struct rt_metrics in, out;
	struct rtentry *rt;
	int64_t asked, boot;

	g_time = nondet_long();
	if (g_time < 0)
		g_time = 0;
	g_uptime = nondet_long();
	if (g_uptime < 0)
		g_uptime = 0;
	boot = g_time - g_uptime;

	rt = CBMC_NEW(struct rtentry);
	memset(&in, 0, sizeof(in));
	asked = nondet_long();
	in.rmx_expire = asked;
	in.rmx_mtu = nondet_uint();

	rtm_setmetrics(RTV_EXPIRE | RTV_MTU, &in, &rt->rt_rmx);

	__CPROVER_assert((rt->rt_expire == 0) == (asked == 0),
	    "S1: stored 0 exactly for 0");
	__CPROVER_assert(asked == 0 || rt->rt_expire > 0,
	    "S2: a nonzero expiry stays nonzero and positive");
	if (asked != 0 && asked > boot &&
	    !(boot < 0 && asked > INT64_MAX + boot))
		__CPROVER_assert(rt->rt_expire == asked - boot,
		    "S3: the same instant in uptime");

	rtm_getmetrics(rt, &out);
	if (asked != 0 && asked > boot &&
	    !(boot < 0 && asked > INT64_MAX + boot))
		__CPROVER_assert(out.rmx_expire == asked,
		    "R: read back unchanged");

	harness_release(rt);
	return (0);
}

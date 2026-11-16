/*
 * Harness: rtm_xaddrs() on an arbitrary buffer and an arbitrary
 * rti_addrs mask.
 *
 * rtm_xaddrs() parses the sockaddrs that follow a routing message
 * written to a routing socket (route_output).  The whole of rtsock.c is
 * #included so that its types, macros and static declarations match.
 *
 * Configuration: config(8) would define INET6 for the kernel compile;
 * cbmc.sh cannot pass -D, so it is defined here, before the include.
 * MPLS, BFD and IPSEC stay undefined: their branches (AF_MPLS, RTAX_BFD,
 * PF_KEY) are not compiled.
 *
 * Buffer: exactly len bytes, len in 0..MAXLEN, arbitrary content.
 * cp = buf, cplim = buf + len.  MAXLEN is 40: an AF_INET6 sockaddr is
 * 28 bytes and a LABEL sockaddr 34, so the buffer holds one large address
 * or several small ones.  A sockaddr_rtstatic or sockaddr_rtsearch (130
 * bytes) cannot fit: the STATIC and SEARCH branches are not reached and
 * not asserted here.  Making MAXLEN 136 ran out of memory in the cover
 * run (6000 MB, the string scans of 129 steps each over a symbolic
 * buffer).
 *
 * Postconditions, asserted only when rtm_xaddrs() returns 0.  The code
 * promises them (each comment names the line that does):
 *  P0  rti_info[i] != NULL exactly for the bits of rti_addrs, and no bit
 *      at or above RTAX_MAX is set (first loop).  Holds for a zeroed
 *      rti_info on entry; see main().
 *  P1  sa lies in the buffer and its first sizeof(socklen_t) bytes too
 *      (first loop, "cp + sizeof(socklen_t) > cplim").
 *  P2  sa + sa_len <= cplim (first loop, "cp + sa->sa_len > cplim").
 *  Second loop, for an address not preceded by a string address:
 *  P3  DST, GATEWAY, SRC: AF_INET sa_len >= sizeof(sockaddr_in),
 *      AF_LINK >= sizeof(sockaddr_dl), AF_INET6 >= sizeof(sockaddr_in6).
 *      Other families: nothing promised, the code accepts them.
 *  P4  IFP: family AF_LINK and sa_len >= 4.
 *  P5  IFA: family AF_INET (sa_len >= 16) or AF_INET6 (>= 28).
 *  P6  LABEL: family AF_UNSPEC, sa_len >= 34, sa_data NUL terminated
 *      within RTLABEL_LEN bytes and within sa_len.
 *  P7  DNS: family AF_INET or AF_INET6, sa_len in [2, 130].
 *  The second loop does "break" after a LABEL, STATIC or SEARCH address
 *  (the if (maxlen) block is inside the for loop, not the switch), so
 *  addresses above that index are not checked; the harness asserts
 *  nothing about them (see "checked" in main()).
 *  NETMASK, GENMASK, AUTHOR, BRD: the code promises nothing beyond P1
 *  and P2; sa_len 0 is accepted and advances the walk by 8 bytes.
 *
 * Models: strnlen is a replace (model_strnlen).  bzero has no model in
 * cbmc.sh; see main().
 */
#define INET6	1
#include "rtsock.c"
#include "cbmc_harness.h"

#define MAXLEN	40

/*
 * Model of strnlen() (replace file).  cbmc.sh has no body for strnlen,
 * so the kernel's string check would see an unconstrained length.  The
 * model returns the index of the first NUL in s[0..maxlen), or maxlen.
 * rtm_xaddrs calls it with maxlen 32 (RTLABEL_LEN): loop unwound 33.
 */
size_t
model_strnlen(const char *s, size_t maxlen)
{
	size_t k;

	for (k = 0; k < maxlen; k++)
		if (s[k] == '\0')
			return (k);
	return (maxlen);
}

/*
 * Index of the first NUL in s[0..n), or -1.  Reads only the n bytes given.
 * n <= RTLABEL_LEN (32) at the one call site, so the loop is unwound 33.
 */
static int
first_nul(const char *s, int n)
{
	int k;

	for (k = 0; k < n; k++)
		if (s[k] == '\0')
			return (k);
	return (-1);
}

/*
 * First NUL in the string of sa (sa_data, at offset 2), within maxlen bytes
 * and within sa_len, or -1.  The scan never reads past sa + sa_len.
 */
static int
string_nul(const struct sockaddr *sa, int maxlen)
{
	int room = (int)sa->sa_len - 2;

	if (room > maxlen)
		room = maxlen;
	return (room > 0 ? first_nul((const char *)sa + 2, room) : -1);
}

static struct rt_addrinfo zero_info;	/* all zero */

int
main(void)
{
	struct rt_addrinfo info;
	caddr_t buf, cplim;
	size_t len;
	int error, i, checked;
	unsigned int bits;

	len = nondet_uint() % (MAXLEN + 1);
	buf = malloc(len, M_TEMP, M_WAITOK);	/* arbitrary content */
	cplim = buf + len;

	/*
	 * route_output zeroes its rt_addrinfo before the call.  bzero() has no
	 * model in common/ (cbmc.sh: "no body for function __builtin_bzero"),
	 * so the zeroing is a struct copy from a static (zero) object.  The
	 * bzero of rti_info inside rtm_xaddrs() is therefore not modelled and
	 * P0 holds for a zeroed rti_info on entry, which is what route_output
	 * provides.
	 */
	info = zero_info;
	info.rti_addrs = nondet_int();
	error = rtm_xaddrs(buf, cplim, &info);
	if (error != 0)
		return (0);

	bits = (unsigned int)info.rti_addrs;
	__CPROVER_assert((bits >> RTAX_MAX) == 0,
	    "P0: no address bit at or above RTAX_MAX");

	/*
	 * checked: the second loop of rtm_xaddrs reaches index i.  It stops
	 * at the first string address (LABEL, the only one reachable here).
	 */
	checked = 1;
	for (i = 0; i < RTAX_MAX; i++) {
		const struct sockaddr *sa = info.rti_info[i];

		__CPROVER_assert(((bits >> i) & 1) == (sa != NULL),
		    "P0: rti_info[i] is set exactly for the bits of rti_addrs");
		if (sa == NULL)
			continue;

		__CPROVER_assert((caddr_t)sa >= buf &&
		    (caddr_t)sa + sizeof(socklen_t) <= cplim,
		    "P1: sockaddr and its first 4 bytes lie in the buffer");
		__CPROVER_assert((caddr_t)sa + sa->sa_len <= cplim,
		    "P2: sockaddr lies in the buffer (sa + sa_len <= cplim)");

		if (!checked)
			continue;
		switch (i) {
		case RTAX_DST:
		case RTAX_GATEWAY:
		case RTAX_SRC:
			switch (sa->sa_family) {
			case AF_INET:
				__CPROVER_assert(sa->sa_len >=
				    sizeof(struct sockaddr_in),
				    "P3: AF_INET address holds sockaddr_in");
				break;
			case AF_LINK:
				__CPROVER_assert(sa->sa_len >=
				    sizeof(struct sockaddr_dl),
				    "P3: AF_LINK address holds sockaddr_dl");
				break;
			case AF_INET6:
				__CPROVER_assert(sa->sa_len >=
				    sizeof(struct sockaddr_in6),
				    "P3: AF_INET6 address holds sockaddr_in6");
				break;
			}
			break;
		case RTAX_IFP:
			__CPROVER_assert(sa->sa_family == AF_LINK,
			    "P4: IFP is AF_LINK");
			__CPROVER_assert(sa->sa_len >= 4,
			    "P4: IFP holds sdl_index (4 bytes)");
			break;
		case RTAX_IFA:
			if (sa->sa_family == AF_INET)
				__CPROVER_assert(sa->sa_len >=
				    sizeof(struct sockaddr_in),
				    "P5: IFA AF_INET holds sockaddr_in");
			else
				__CPROVER_assert(sa->sa_family == AF_INET6 &&
				    sa->sa_len >= sizeof(struct sockaddr_in6),
				    "P5: IFA is AF_INET or AF_INET6 sized");
			break;
		case RTAX_LABEL:
			__CPROVER_assert(sa->sa_family == AF_UNSPEC,
			    "P6: LABEL is AF_UNSPEC");
			__CPROVER_assert(sa->sa_len >=
			    sizeof(struct sockaddr_rtlabel),
			    "P6: LABEL holds sockaddr_rtlabel");
			__CPROVER_assert(string_nul(sa, RTLABEL_LEN) >= 0,
			    "P6: LABEL NUL terminated within RTLABEL_LEN and sa_len");
			checked = 0;
			break;
		case RTAX_DNS:
			__CPROVER_assert(sa->sa_family == AF_INET ||
			    sa->sa_family == AF_INET6,
			    "P7: DNS is AF_INET or AF_INET6");
			__CPROVER_assert(sa->sa_len <=
			    sizeof(struct sockaddr_rtdns) &&
			    sa->sa_len >= offsetof(struct sockaddr_rtdns, sr_dns),
			    "P7: DNS sa_len within sockaddr_rtdns");
			break;
		default:
			break;
		}
	}
	return (0);
}

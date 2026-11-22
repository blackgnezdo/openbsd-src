/*
 * Harness: carp_proto_input_if() and carp_proto_input_c() of
 * sys/netinet/ip_carp.c on one IPv4 packet, on the mbuf contract models
 * (common/mbufcontract.h).
 *
 * The packet: an IP header of 20 bytes (ip_hl 5, *offp 20) followed by
 * 0..48 CARP bytes of arbitrary content (struct carp_header is 36 bytes,
 * so 0..12 bytes of slack too): 20..68 bytes, one or two mbufs, the
 * first of arbitrary length.  Every mbuf's data ends where its object
 * ends, so a read past m_len is out of bounds.  Caller contract
 * (ip_input.c, ipv4_check): the IP header is contiguous in the first
 * mbuf, m_pkthdr.len is the packet length, ip_len is that length in
 * network order (carp does not read it).  ip_ttl, ip_dst are arbitrary.
 *
 * Interface: ifp is one of three: an IFT_ETHER parent whose if_carp list
 * is empty or holds the one softc, an IFT_CARP interface (the code then
 * goes through if_get(if_carpdevidx) to the parent, which may have
 * vanished) or another type (the badif drop).  The softc's fields are
 * arbitrary within their ranges: sc_peer, sc_advbase 0..255, sc_naddrs,
 * sc_suppress, sc_demote_cnt 0..300, if_flags UP/RUNNING, a group with
 * ifg_carp_demoted 0..300 or none; one vhost entry with vhid 0..255,
 * advskew 0..255, state INIT/BACKUP/MASTER, an arbitrary replay cookie,
 * arbitrary key pad and arbitrary SHA1 state (count 512: one pad block
 * hashed, as carp_hmac_ctx leaves it).
 *
 * Models: in_cksum asserts that len bytes are in the chain and returns
 * zero or an arbitrary value (never zero for len < 2); if_get returns
 * NULL or the parent with a counted reference, if_put drops it;
 * carp_set_state asserts that the state changes and stores it (the
 * link state and lsmask update are left out); carp_send_ad and
 * carp_send_arp assert their arguments.  counters, log, timeouts and
 * getmicrotime have no body (nobody).  Real: both input functions, the
 * lookup, carp_master_down,
 * carp_setrun, carp_group_demote_count.  carp_hmac_verify is a model
 * under CBMC (below), the real body with real SHA1 natively.
 *
 * Natively the harness also makes the packet pass the gates a fuzzer
 * would not find by chance: version 2, the vhid of the entry, the
 * HMAC of the counter (CBMC finds these itself).
 *
 * Asserted: no out-of-bounds access, no leak or double free, the packet
 * is consumed, interface references balanced, return IPPROTO_DONE.
 */
#define MC_MAXLEN	68	/* 20 byte IP header + 48 bytes of CARP */
#define CARP_EXTRA_MAX	48
#include "mbufcontract.h"

#include "ip_carp.c"

static struct arpcom model_parent;	/* the IFT_ETHER parent */
static struct arpcom model_cif;		/* the IFT_CARP interface */
static int g_ifrefs;

int
model_in_cksum(struct mbuf *m, int len)
{
	struct mbuf *n;
	int left = len, k;

	__CPROVER_assert(len >= 0, "in_cksum: length");
	for (n = m; n != NULL && left > 0; n = n->m_next) {
		k = n->m_len < left ? n->m_len : left;
		if (k > 0)
			__CPROVER_assert(__CPROVER_r_ok(mtod(n, u_char *), k),
			    "in_cksum: bytes readable");
		left -= k;
	}
	__CPROVER_assert(left == 0, "in_cksum: chain shorter than len");
	if (len < 2)
		return (0xffff);
	if (nondet_bool())
		return (0);
	return (nondet_int());
}

struct ifnet *
model_if_get(unsigned int index)
{
	if (nondet_bool())
		return (NULL);
	g_ifrefs++;
	return (&model_parent.ac_if);
}

void
model_if_put(struct ifnet *ifp)
{
	if (ifp == NULL)
		return;
	__CPROVER_assert(ifp == &model_parent.ac_if && g_ifrefs > 0,
	    "if_put model: a reference is held");
	g_ifrefs--;
}

void
model_carp_set_state(struct carp_vhost_entry *vhe, int state)
{
	__CPROVER_assert(vhe != NULL && vhe->parent_sc != NULL,
	    "carp_set_state: vhe");
	__CPROVER_assert(vhe->state != state, "carp_set_state: KASSERT");
	__CPROVER_assert(state == INIT || state == BACKUP || state == MASTER,
	    "carp_set_state: state");
	vhe->state = state;
}

/*
 * carp_hmac_verify(): under CBMC it asserts that its inputs are
 * readable and returns 0 (match) or 1 (no match) arbitrarily: real SHA1
 * made the check run time out (2.8 million variables, 600 s).
 * Natively it is the kernel's body, SHA1 included.
 */
int
model_carp_hmac_verify(struct carp_vhost_entry *vhe, u_int32_t counter[2],
    unsigned char md[20])
{
#ifdef NATIVE_SHIM_H
	unsigned char md2[20];
	u_int8_t i;

	for (i = 0; i < HMAC_MAX; i++) {
		carp_hmac_generate(vhe, counter, md2, i);
		if (!timingsafe_bcmp(md, md2, sizeof(md2)))
			return (0);
	}
	return (1);
#else
	__CPROVER_assert(vhe != NULL, "carp_hmac_verify: vhe");
	__CPROVER_assert(__CPROVER_r_ok(counter, 2 * sizeof(u_int32_t)),
	    "carp_hmac_verify: counter readable");
	__CPROVER_assert(__CPROVER_r_ok(md, 20),
	    "carp_hmac_verify: md readable");
	return (nondet_bool() ? 1 : 0);
#endif
}

void
model_carp_send_ad(struct carp_vhost_entry *vhe)
{
	__CPROVER_assert(vhe != NULL && vhe->parent_sc != NULL,
	    "carp_send_ad: vhe");
}

void
model_carp_send_arp(struct carp_softc *sc)
{
	__CPROVER_assert(sc != NULL, "carp_send_arp: sc");
}

#ifdef NATIVE_SHIM_H
/* write n bytes at packet offset off (native only: gates for the fuzzer) */
static void
put_bytes(struct mbuf *m, int off, const u_char *p, int n)
{
	int i, o;
	struct mbuf *c;

	for (i = 0; i < n; i++) {
		c = m;
		o = off + i;
		while (c != NULL && o >= c->m_len) {
			o -= c->m_len;
			c = c->m_next;
		}
		if (c != NULL)
			mtod(c, u_char *)[o] = p[i];
	}
}
#endif

int
main(void)
{
	struct mbuf *m;
	struct ip *ip;
	struct carp_softc *sc = NULL;
	struct carp_vhost_entry *vhe = NULL;
	struct ifg_list *ifgl = NULL;
	struct ifnet *ifp;
	int len, off, ret, kind;

	model_parent.ac_if.if_type = IFT_ETHER;
	model_parent.ac_if.if_index = 1;
	model_cif.ac_if.if_type = IFT_CARP;
	model_cif.ac_if.if_carpdevidx = 1;

	if (mc_upto(1)) {
		sc = CBMC_NEW(struct carp_softc);
		vhe = CBMC_NEW(struct carp_vhost_entry);
		sc->sc_if.if_type = IFT_CARP;
		sc->sc_carpdevidx = 1;
		sc->sc_if.if_flags = nondet_ushort();
		sc->sc_peer.s_addr = nondet_uint();
		sc->sc_advbase = mc_upto(255);
		sc->sc_naddrs = mc_upto(2);
		sc->sc_naddrs6 = mc_upto(2);
		sc->sc_suppress = mc_upto(1);
		sc->sc_demote_cnt = mc_upto(300);
		sc->sc_balancing = mc_upto(2);
		sc->sc_vhe_count = 1;
		TAILQ_INIT(&sc->sc_if.if_groups);
		if (mc_upto(1)) {
			ifgl = CBMC_NEW(struct ifg_list);
			ifgl->ifgl_group = CBMC_NEW(struct ifg_group);
			ifgl->ifgl_group->ifg_carp_demoted = mc_upto(300);
			TAILQ_INSERT_HEAD(&sc->sc_if.if_groups, ifgl,
			    ifgl_next);
		}
		vhe->parent_sc = sc;
		vhe->vhe_leader = mc_upto(1);
		vhe->vhid = mc_upto(255);
		vhe->advskew = mc_upto(255);
		vhe->state = mc_upto(2);
		vhe->vhe_replay_cookie = nondet_u64();
		{
			int i;

			for (i = 0; i < CARP_HMAC_PAD; i++)
				vhe->vhe_pad[i] = nondet_uchar();
			for (i = 0; i < HMAC_MAX; i++) {
				int k;

				for (k = 0; k < 5; k++)
					vhe->vhe_sha1[i].state[k] =
					    nondet_uint();
				vhe->vhe_sha1[i].count = 512;
				/* the buffer is dead after a transform */
			}
		}
		sc->carp_vhosts.smr_slh_first = vhe;
		model_parent.ac_if.if_carp.smr_lh_first = sc;
	}

	kind = mc_upto(2);
	if (kind == 0)
		ifp = &model_parent.ac_if;
	else if (kind == 1)
		ifp = &model_cif.ac_if;
	else {
		model_cif.ac_if.if_type = IFT_LOOP;
		ifp = &model_cif.ac_if;
	}

	len = sizeof(struct ip) + mc_upto(CARP_EXTRA_MAX);
	/*
	 * ipv4_check: the IP header is contiguous in the first mbuf.  The
	 * chain is built here (what mc_build does, the first mbuf at
	 * least 20 bytes) instead of with a harness m_pullup: one copy
	 * less in the formula.
	 */
	off = sizeof(struct ip) + mc_upto(len - sizeof(struct ip));
	m = mc_seg(off);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = len;
	m->m_pkthdr.ph_ifidx = 0;
	if (off < len)
		m->m_next = mc_seg(len - off);
	ip = mtod(m, struct ip *);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_len = htons(len);
	ip->ip_p = IPPROTO_CARP;
	ip->ip_ttl = mc_upto(1) ? CARP_DFLTTL : nondet_uchar();
	ip->ip_src.s_addr = nondet_uint();
	ip->ip_dst.s_addr = nondet_uint();

#ifdef NATIVE_SHIM_H
	if (len >= sizeof(struct ip) + sizeof(struct carp_header)) {
		u_char b, md[20];
		u_int32_t counter[2];

		if (mc_upto(1)) {
			m_copydata(m, sizeof(struct ip), 1, &b);
			b = (b & 0x0f) | (CARP_VERSION << 4);
			put_bytes(m, sizeof(struct ip), &b, 1);
		}
		if (vhe != NULL && mc_upto(1)) {
			b = vhe->vhid;
			put_bytes(m, sizeof(struct ip) + 1, &b, 1);
		}
		if (vhe != NULL && mc_upto(1)) {
			m_copydata(m, sizeof(struct ip) + 8, 8, counter);
			carp_hmac_generate(vhe, counter, md, mc_upto(1));
			put_bytes(m, sizeof(struct ip) + 16, md, 20);
		}
	}
#endif

	off = sizeof(struct ip);
	ret = carp_proto_input_if(ifp, &m, &off, IPPROTO_CARP);
	__CPROVER_assert(ret == IPPROTO_DONE, "carp_proto_input_if: IPPROTO_DONE");
	/* the packet was consumed on every path */

	__CPROVER_assert(g_ifrefs == 0, "interface references balanced");
	if (ifgl != NULL) {
		mc_release(ifgl->ifgl_group);
		mc_release(ifgl);
	}
	if (vhe != NULL)
		mc_release(vhe);
	if (sc != NULL)
		mc_release(sc);
	return (0);
}

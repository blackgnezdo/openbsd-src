/*
 * mbuf(9) model, built with kernel headers.  Selected per target with a
 * line "mbuf" in <target>/models.
 *
 * An mbuf is one allocation with its data in m_dat (MLEN bytes); a
 * cluster is a second allocation of the requested size.  M_DONTWAIT
 * requests may fail.  Loops over a chain (m_freem) need an unwind bound.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

_Bool nondet_bool(void);

struct mbuf *
m_get(int nowait, int type)
{
	struct mbuf *m;

	if (nowait == M_DONTWAIT && nondet_bool())
		return (NULL);
	m = malloc(sizeof(*m), M_TEMP, M_WAITOK | M_ZERO);
	m->m_type = type;
	m->m_data = m->m_dat;
	return (m);
}

struct mbuf *
m_clget(struct mbuf *m, int how, u_int pktlen)
{
	caddr_t buf;

	if (m == NULL && (m = m_get(how, MT_DATA)) == NULL)
		return (NULL);
	if (how == M_DONTWAIT && nondet_bool())
		return (m);		/* no cluster: M_EXT stays clear */
	buf = malloc(pktlen, M_TEMP, M_WAITOK);
	m->m_data = buf;
	m->m_ext.ext_buf = buf;
	m->m_ext.ext_size = pktlen;
	m->m_flags |= M_EXT;
	return (m);
}

struct mbuf *
m_free(struct mbuf *m)
{
	struct mbuf *n;

	if (m == NULL)
		return (NULL);
	n = m->m_next;
	if (m->m_flags & M_EXT)
		free(m->m_ext.ext_buf, M_TEMP, m->m_ext.ext_size);
	free(m, M_TEMP, sizeof(*m));
	return (n);
}

struct mbuf *
m_freem(struct mbuf *m)
{
	while (m != NULL)
		m = m_free(m);
	return (NULL);
}

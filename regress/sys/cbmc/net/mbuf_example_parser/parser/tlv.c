/*
 * A stand-in for a kernel packet parser, written the way the kernel
 * writes them: a 4-byte header at offset off, then one TLV (type byte,
 * length byte, value).  A type 1 value is used in place, so it is pulled
 * up into the first mbuf; other values are copied out.  Returns 0 or an
 * error; *mp may change (m_pullup), and is NULL if the chain was freed.
 */
#define TLV_HDRLEN	4
#define TLV_MAXVAL	8

volatile u_int8_t tlv_sink;

int
tlv_parse(struct mbuf **mp, int off)
{
	struct mbuf *m = *mp;
	u_int8_t th[2], val[TLV_MAXVAL];
	int type, len;

	if (off + TLV_HDRLEN + 2 > m->m_pkthdr.len)
		return (EINVAL);
	off += TLV_HDRLEN;
	m_copydata(m, off, 2, th);
	type = th[0];
	len = th[1];
	if (off + 2 + len > m->m_pkthdr.len)
		return (EINVAL);
	if (type == 1) {
		if (m->m_len < off + 2 + len &&
		    (m = *mp = m_pullup(m, off + 2 + len)) == NULL)
			return (ENOBUFS);
		/* the value is used in place */
		if (len > 0)
			tlv_sink = mtod(m, u_int8_t *)[off + 2 + len - 1];
	} else {
		if (len > TLV_MAXVAL)
			return (EINVAL);
		m_copydata(m, off + 2, len, val);
	}
	return (0);
}

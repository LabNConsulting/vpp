/*
 * macsec_encrypt.c : MACsec encrypt node using DPDK Cryptodev
 *
 * Copyright (c) 2020, LabN Consulting, L.L.C.
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp.h>
#include <dpdk/buffer.h>
#include <dpdk/ipsec/ipsec.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <iptfs/ipsec_iptfs.h>
#include <vnet/macsec/macsec.h>
#include <vnet/macsec/macsec_format.h>

#define foreach_macsec_encrypt_next				\
_(DROP, "error-drop")						\
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) MACSEC_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_macsec_encrypt_next
#undef _
    MACSEC_ENCRYPT_N_NEXT,
} macsec_encrypt_next_t;

#define foreach_macsec_encrypt_error				\
 _(RX_PKTS, "MACSEC pkts received")				\
 _(SEQ_CYCLED, "Sequence number cycled")			\
 _(ENQ_FAIL, "Enqueue encrypt failed (queue full)")		\
 _(DISCARD, "Not enough crypto operations")			\
 _(SESSION, "Failed to get crypto session")			\
 _(NODST, "Failed to get dst buffer for chained source")	\
 _(NOSUP, "Cipher/Auth not supported")


typedef enum
{
#define _(sym,str) MACSEC_ENCRYPT_ERROR_##sym,
  foreach_macsec_encrypt_error
#undef _
    MACSEC_ENCRYPT_N_ERROR,
} macsec_encrypt_error_t;

static char *macsec_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_macsec_encrypt_error
#undef _
};

extern vlib_node_registration_t dpdk_macsec_encrypt_node;

typedef enum
{
    METS_NORMAL = 0,
    METS_RESOURCE,
    METS_SESSION,
    METS_DSTBUF,
} dpdk_macsec_encrypt_trace_status_t;

typedef struct
{
  dpdk_macsec_encrypt_trace_status_t	trace_status;
  ipsec_crypto_alg_t crypto_alg;
  u16	orig_size;			/* valid: METS_DSTBUF, METS_NORMAL */
  u16	trunc_size;			/* digest should always be 16 */
  u16	adv;
  u16	handoff_length;			/* mbuf packet length to encryptor */

  u8	iv[12];
  u8	packet_data[64];
  u8	packet_data_last[16];
  u8	packet_data_digest[16];
  u8	ad[28];

  void	*src_mb0;
  rte_iova_t	src_mb0_data_iova;

  void	*dst_mb0;
  rte_iova_t	dst_mb0_data_iova;

  /* copy from crypto op after it is set up. Valid for METS_NORMAL */
  struct rte_crypto_op		*p_crypto_op;
  struct rte_crypto_op		crypto_op;
  struct rte_crypto_sym_op	crypto_sym_op;

  u8		*mbuf_buf_addr;
  u8		*mbuf_buf_physaddr;
  u8		*digest;
  int		digest_offset_from_buf_addr;
  u8		*digest_paddr;
  u8		*mvsam_digest;

} macsec_encrypt_trace_t;

static u8 *
format_macsec_encrypt_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    macsec_encrypt_trace_t *t = va_arg (*args, macsec_encrypt_trace_t *);
    u32 indent = format_get_indent (s);
    char *status;

    /* TBD we should condition printing various fields below on this value */
    switch (t->trace_status) {
	case METS_NORMAL:	status = "normal"; break;
	case METS_RESOURCE:	status = "no resource"; break;
	case METS_SESSION:	status = "no session"; break;
	case METS_DSTBUF:	status = "no dstbuf"; break;
	default:		status = "unknown"; break;
    }

    s = format (s, "%U\n", format_ethernet_header, t->packet_data);

    s = format (s, "%Ustatus: %s, trunc_size %u, adv %u, dst_mb0 %p\n",
	format_white_space, indent,
	status, t->trunc_size, t->adv, t->dst_mb0);
    s = format (s, "%Usrc_mb0: %p, src_mb0_data_iova: %p\n",
	format_white_space, indent+2,
	t->src_mb0,
	t->src_mb0_data_iova);
    s = format (s, "%Udst_mb0: %p, dst_mb0_data_iova: %p\n",
	format_white_space, indent+2,
	t->dst_mb0,
	t->dst_mb0_data_iova);

    if (t->trace_status == METS_NORMAL ||
	t->trace_status == METS_DSTBUF) {

	s = format (s, "%Uorig_sz: %u\n",
	    format_white_space, indent,
	    t->orig_size);
    }

    s = format (s, "%Ucipher %U\n",
	format_white_space, indent,
	format_ipsec_crypto_alg, t->crypto_alg);

    s = format (s, "%U%U",
	format_white_space, indent,
	format_macsec_header_force_sc, t->ad);

    if (t->trace_status == METS_NORMAL) {
	/* TBD use actual packet length if shorter here: */
	s = format (s, "%Uhandoff_length (incl ICV area): %u\n",
	    format_white_space, indent,
	    t->handoff_length);

	s = format (s, "%UPacket Dump (initial bytes)\n%U\n",
	    format_white_space, indent,
	    format_hexdump, t->packet_data, sizeof(t->packet_data));

	s = format (s, "%ULast %d bytes of original packet (valid for non-chain)\n%U\n",
	    format_white_space, indent,
	    sizeof(t->packet_data_last),
	    format_hexdump, t->packet_data_last, sizeof(t->packet_data_last));

	s = format (s, "%U%d bytes digest area (before encryption)\n%U\n",
	    format_white_space, indent,
	    sizeof(t->packet_data_digest),
	    format_hexdump, t->packet_data_digest, sizeof(t->packet_data_digest));


	/* OP has been set up. Display saved values */
	s = format(s, "%UOP: type: %u, status: %u, sess_type: %u, addr: %p, phys_addr: %p\n",
	    format_white_space, indent,
	    t->crypto_op.type,
	    t->crypto_op.status,
	    t->crypto_op.sess_type,
	    t->p_crypto_op,
	    t->crypto_op.phys_addr);

	s = format(s, "%USYM_OP: m_src: %p, m_dst: %p, session: %p\n",
	    format_white_space, indent,
	    t->crypto_sym_op.m_src,
	    t->crypto_sym_op.m_dst,
	    t->crypto_sym_op.session);
	s = format(s, "%Uaead.data.offset: %u, aead.data.length: %u\n",
	    format_white_space, indent+2,
	    t->crypto_sym_op.aead.data.offset,
	    t->crypto_sym_op.aead.data.length);
	s = format(s, "%Uaead.aad.data: %p, aead.aad.phys_addr: %p\n",
	    format_white_space, indent+2,
	    t->crypto_sym_op.aead.aad.data,
	    t->crypto_sym_op.aead.aad.phys_addr);
	s = format(s, "%Uaead.digest.data: %p, aead.digest.phys_addr: %p\n",
	    format_white_space, indent+2,
	    t->crypto_sym_op.aead.digest.data,
	    t->crypto_sym_op.aead.digest.phys_addr);
	s = format(s, "%Umbuf_buf_addr %p, mbuf_buf_physaddr %p\n%Udigest %p, digest offset %d\n%Udigest_paddr %p, mvsam_digest %p\n",
	    format_white_space, indent+2,
	    t->mbuf_buf_addr,
	    t->mbuf_buf_physaddr,
	    format_white_space, indent+2,
	    t->digest,
	    t->digest_offset_from_buf_addr,
	    format_white_space, indent+2,
	    t->digest_paddr,
	    t->mvsam_digest);
    }

    return s;
}

always_inline uword
dpdk_macsec_encrypt_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  u32			n_left_from, *from, *to_next, next_index, thread_index;
  ipsec_main_t		*im = &ipsec_main;
  u32			thread_idx = vlib_get_thread_index ();
  dpdk_crypto_main_t	*dcm = &dpdk_crypto_main;
  crypto_resource_t	*res = 0;
  ipsec_sa_t		*sa0 = 0;
  crypto_alg_t		*cipher_alg = 0;
  crypto_alg_t		*auth_alg = 0;
  struct rte_cryptodev_sym_session	*session = 0;
  u32			ret, last_sa_index = ~0;
  u8			numa = rte_socket_id ();
  u8			is_aead = 0;
  crypto_worker_main_t	*cwm = vec_elt_at_index(dcm->workers_main, thread_idx);
  struct rte_crypto_op	**ops = cwm->ops;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  ret = crypto_alloc_ops (numa, ops, n_left_from);
  if (ret)
    {
      vlib_node_increment_counter (vm, dpdk_macsec_encrypt_node.index,
				     MACSEC_ENCRYPT_ERROR_DISCARD, n_left_from);
      /* Discard whole frame */
      vlib_buffer_free (vm, from, n_left_from);
      return n_left_from;
    }

  next_index = MACSEC_ENCRYPT_NEXT_DROP;	/* default */

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  clib_error_t		*error;
	  u32			bi0, bi1;
	  vlib_buffer_t		*b0, *b1;
	  u32			sa_index0;
	  ethernet_header_t	*eh0;
	  u16			orig_sz = 0;
	  u8			trunc_size = 0;
	  struct rte_mbuf	*mb0;
	  struct rte_mbuf	*dst_mb0 = NULL;
	  struct rte_crypto_op	*op;
	  u16			res_idx;
	  u16			adv = 0;
	  u8			*aad = NULL;
	  dpdk_macsec_encrypt_trace_status_t	trace_status = METS_NORMAL;
	  u32			packet_number = ~0;

	  u32 cipher_off;
	  u32 cipher_len;
	  u8 *digest = NULL;
	  u64 digest_paddr = 0;
	  u16 avail;

	  vlib_buffer_t		*lastb0, *dst_b0;
	  struct rte_mbuf	*lastmb0 = NULL;
	  u32			dst_bi0 = ~0u;


	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  eh0 = vlib_buffer_get_current (b0);
	  mb0 = rte_mbuf_from_vlib_buffer (b0);

	  /* eh0 */
	  CLIB_PREFETCH (eh0, sizeof (eh0[0]), LOAD);
	  /* mb0 */
	  CLIB_PREFETCH (mb0, CLIB_CACHE_LINE_BYTES, STORE);
	  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	    CLIB_PREFETCH (vlib_buffer_get_tail (b0), 20, STORE);

	  if (n_left_from > 1)
	    {
	      bi1 = from[1];
	      b1 = vlib_get_buffer (vm, bi1);

	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (b1->data - CLIB_CACHE_LINE_BYTES,
			     CLIB_CACHE_LINE_BYTES, STORE);
	    }

	  op = ops[0];
/* TBD is the following a memory leak if we fail later and don't use op? */
	  ops += 1;
	  ASSERT (op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  dpdk_op_priv_t *priv = crypto_op_get_priv (op);
	  /* store bi in op private */
	  priv->bi = bi0;
	  priv->encrypt = 1;

	  u16 op_len =
	    sizeof (op[0]) + sizeof (op[0].sym[0]) + sizeof (priv[0]);
	  CLIB_PREFETCH (op, op_len, STORE);

	  /* we overload the ipsec sa index for macsec */
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;

	  orig_sz = dpdk_buffer_length_in_chain_fixup (vm, b0, &lastb0);
	  lastmb0 = rte_mbuf_from_vlib_buffer (lastb0);

	  if (sa_index0 != last_sa_index)
	    {
	      sa0 = pool_elt_at_index (im->sad, sa_index0);

	      cipher_alg =
		vec_elt_at_index (dcm->cipher_algs, sa0->crypto_alg);
	      auth_alg = vec_elt_at_index (dcm->auth_algs, sa0->integ_alg);

	      /* This should always be true */
	      is_aead = (cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD);

#if MACSEC_ALLOW_NON_AEAD	/* For debugging ONLY! */
	      if (is_aead)
		auth_alg = cipher_alg;
#else
	      ASSERT(is_aead);
	      auth_alg = cipher_alg;
#endif

	      res_idx = get_resource (cwm, sa0);

	      if (PREDICT_FALSE (res_idx == (u16) ~ 0))
		{
		  clib_warning ("unsupported SA %u by thread index %u",
				sa_index0, thread_idx);
		  vlib_node_increment_counter (vm,
						 dpdk_macsec_encrypt_node.index,
						 MACSEC_ENCRYPT_ERROR_NOSUP, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  trace_status = METS_RESOURCE;
		  goto trace;
		}
	      res = vec_elt_at_index (dcm->resource, res_idx);

	      error = crypto_get_session (&session, sa_index0, res, cwm, 1);
	      if (PREDICT_FALSE (error || !session))
		{
		  clib_warning ("failed to get crypto session");
		  vlib_node_increment_counter (vm,
						 dpdk_macsec_encrypt_node.index,
						 MACSEC_ENCRYPT_ERROR_SESSION,
						 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  trace_status = METS_SESSION;
		  goto trace;
		}

	      last_sa_index = sa_index0;
	    }

	  /* The NULL cipher device doesn't copy to a dest buffer */
	  if (lastb0 != b0 && cipher_alg->alg != RTE_CRYPTO_CIPHER_NULL)
	    {
	      /* We have a chain, we need a destination buffer */
	      /* Assumes result fits in one buffer (i.e., >9K buffer size) */
	      if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &dst_bi0, 1)))
		{
		  clib_warning
		    ("unable to get destination crypt obuffer SA "
		     "%u by thread index %u",
		     sa_index0, thread_idx);
		  vlib_node_increment_counter (vm,
						 dpdk_macsec_encrypt_node.index,
						 MACSEC_ENCRYPT_ERROR_NODST, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  trace_status = METS_DSTBUF;
		  goto trace;
		}
	      dst_b0 = dpdk_ipsec_get_dst_buffer (vm, dst_bi0, &dst_mb0, b0);
	      /* This is the buffer that will get sent on to the next node */
	      priv->bi = dst_bi0;
	    }

	  /* -------------------- */
	  /* No fail from here on */
	  /* -------------------- */

	  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					   sa_index0, 1, orig_sz);

	  res->ops[res->n_ops] = op;
	  /* this is an expensive optimization just for freeing fast on error */
	  res->bi[res->n_ops] = bi0;
	  res->n_ops += 1;

	  trunc_size = auth_alg->trunc_size;
#if ! MACSEC_ALLOW_NON_AEAD	/* For debugging ONLY! */
	  ASSERT(trunc_size == 16);	/* gpz sanity check, remove when done */
#endif

	  /* new macsec section */

	  /*
	   * Buffer length includes ethernet header. Secure Data length
	   * includes original ethertype but not src/dst addresses
	   */
	  u32 secure_data_length = orig_sz - 12;

	  /*
	   * Build new packet header in aad area. Comprises:
	   *   dst ethernet addr (6 octets)
	   *   src ethernet addr (6 octets)
	   *   security tag (16 octets) comprises:
	   *     macsec ethertype (2 octets)
	   *     tci/an (1 octet)
	   *     short length (1 octet)
	   *     packet number (4 octets)
	   *     SCI (8 octets) - optional in pkt, but mandatory in AAD:
	   *       src mac address (6 octets)
	   *       port id (2 octets)
	   *
	   * Note that the src and dst addresses of the original packet have
	   * already been set to the tunnel endpoints by ETFS. If non-etfs
	   * use macsec, we will need to change code here to get correct
	   * src/dst addresses.
	   */
	  aad = priv->macsec.aad;

	  /* hope we can count on at least even alignment below */

          clib_memcpy_fast(aad, (char *)eh0, 12); /* dst, src ethaddr */
	  *(u16 *)(aad + 12) = clib_host_to_net_u16(MACSEC_ETYPE);
	  aad[14] = MACSEC_TCI_AN_DEFAULT;
	  if (secure_data_length < 48) /* short length */
	    aad[15] = secure_data_length & 0x3f;
	  else
	    aad[15] = 0;
	  packet_number = clib_host_to_net_u32(ipsec_sa_macsec_next_pn(sa0));
	  clib_memcpy(aad + 16, (char *)&packet_number, sizeof(u32));
	  /* src ethernet addr: same issue as noted above vis a vis etfs */
	  clib_memcpy(aad + 20, ((char *)eh0) + 6, 6);
	  *(u16 *)(aad + 26) = clib_host_to_net_u16(0x0001); /* ES=1,SCB=0 => port 1 */

	  /*
	   * Set up IV
	   */

	  dpdk_gcm_cnt_blk *icb = &priv->cb;

	  /* See ieee 802.1ae section 14.5 */
	  clib_memcpy_fast(icb->raw, aad + 20, 8);	/* SCI */
	  clib_memcpy(icb->raw + 8, &packet_number, 4);	/* PN */

	  priv->next = DPDK_CRYPTO_INPUT_NEXT_INTERFACE_OUTPUT;

	  /* macsec tag gets inserted before encrypted data */
	  adv = MACSEC_TAG_NOSCI_LENGTH;


	  /*
	   * Shift start mark of buffer earlier to accomodate insertion of
	   * security tag. Must do this even when there is a dst buffer
	   * so that cipher_off for src and dst indicate corresponding
	   * points in the buffers.
	   *
	   * New header will be copied from AAD below
	   */
	  eh0 = vlib_buffer_push_uninit (b0, adv);

	  /* fixup the first mbuf for the buffer advance done above */
	  mb0->data_len += adv;
	  mb0->pkt_len += adv;
	  mb0->data_off -= adv;

	  /*
	   * Arithmetic for trailing digest (appended by crypto engine).
	   * Operate on src mbuf. If there is separate dst buffer,
	   * its length will be adjusted accordingly below.
	   */

	  avail = vlib_buffer_put_space_avail(vm, lastb0);

	  if (avail < trunc_size)
	    {
	      clib_warning
		("%s: XXX BUG avail: %u ask %u, cdata %u clen %u %u",
		 __FUNCTION__, avail, trunc_size,
		 b0->current_data, b0->current_length,
		 b0->total_length_not_including_first_buffer);
	    }

	  /* extend buffer */
	  digest = vlib_buffer_put_uninit (lastb0, trunc_size);

	  lastmb0->data_len += trunc_size;
	  if (lastmb0 != mb0)
	    lastmb0->pkt_len += trunc_size;
	  mb0->pkt_len += trunc_size;

	  if (b0 != lastb0)
	    b0->total_length_not_including_first_buffer += trunc_size;

	  /* TBD why is this true now if not before? */
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  if (dst_mb0) {
	    /* recompute header to point into destination buffer */
	    eh0 = vlib_buffer_get_current(dst_b0);

	    /* set length of dest vlib buffer based on adjusted src pkt len */
	    dst_b0->current_length = mb0->pkt_len;

	    /* set up dest mbuf header based on vlib buffer header */
	    dpdk_validate_rte_mbuf (vm, dst_b0, 0);

	    /* recompute digest to point into destination buffer */
	    digest = vlib_buffer_get_tail (dst_b0) - trunc_size;
	    digest_paddr =
		dst_mb0->buf_physaddr + digest - ((u8 *) dst_mb0->buf_addr);

	  } else {
	    /* in-place */

	      digest_paddr =
		lastmb0->buf_physaddr + digest - ((u8 *) lastmb0->buf_addr);

	  }

	  /*
	   * copy the dst/src addresses and the security tag into the first
	   * part of the buffer (either in-place buf or dst buf). Omit SCI.
	   * (SCI is optional for point-to-point).
	   *
	   * The copied data is the leading part of AAD constructed above.
	   */
	  clib_memcpy_fast(eh0, aad, 12 + adv);

	  cipher_off = 12 + adv;	/* start @ orig etype */
	  cipher_len = secure_data_length;

	  crypto_op_setup (is_aead, mb0, dst_mb0, op, session,
	    cipher_off, cipher_len,
	    0 /* auth_off unused */, 0 /* auth_len unused */,
	    (u8 *) aad,
	    digest, digest_paddr);

#if 0
	  /* GMAC not supported in VPP so, at the moment, always increment
	   * txsc_out_pkts_encrypted.
	   */
          MACSEC_INC_SIMPLE_COUNTER(gen_out_octets_protected, thread_index,
                                    vnet_buffer (b0)->sw_if_index[VLIB_TX],
                                    orig_sz);
          MACSEC_INC_COMBINED_COUNTER(txsc_out_pkts_protected, thread_index,
                                    vnet_buffer (b0)->sw_if_index[VLIB_TX],
                                    1, orig_sz);
#endif
          MACSEC_INC_COMBINED_COUNTER(txsc_out_pkts_encrypted, thread_index,
                                    vnet_buffer (b0)->sw_if_index[VLIB_TX],
                                    1, orig_sz);

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      macsec_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));

	      /* indicates which fields are valid to trace formatter */
	      tr->trace_status = trace_status;

	      tr->p_crypto_op = op;
	      tr->crypto_op = *op;

	      struct rte_crypto_sym_op *sym_op =
		(struct rte_crypto_sym_op *) (op + 1);
	      tr->crypto_sym_op = *sym_op;

	      /*
	       * XXX beware of uninitialized values when we reach here via goto
	       */
	      tr->orig_size = orig_sz;
	      tr->adv = adv;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->trunc_size = trunc_size;

	      /* TBD clib_memcpy_fast(tr->iv, icb->raw, sizeof(tr->iv)); */

	      tr->src_mb0 = mb0;
	      tr->src_mb0_data_iova = rte_mbuf_data_iova(mb0);

	      tr->dst_mb0 = dst_mb0;
	      if (dst_mb0)
		  tr->dst_mb0_data_iova = rte_mbuf_data_iova(dst_mb0);

	      tr->handoff_length = mb0->pkt_len; /* includes ICV area */

	      u8 *p = vlib_buffer_get_current (b0);

	      /* point at original packet header (new one is in dst mb0) */
	      if (dst_mb0)
		p += adv;

	      clib_memcpy_fast (tr->packet_data, p, sizeof (tr->packet_data));
	      if (aad)
		  clib_memcpy_fast (tr->ad, aad, sizeof (tr->ad));

	      /*
	       * XXX This is only valid when last 16 bytes of original
	       * packet are in same buffer as digest
	       */
	      p = digest - sizeof(tr->packet_data_last);
	      clib_memcpy_fast(tr->packet_data_last, p,
		sizeof(tr->packet_data_last));

	      clib_memcpy_fast(tr->packet_data_digest, digest,
		sizeof(tr->packet_data_digest));

	      if (dst_mb0) {
		tr->mbuf_buf_addr = dst_mb0->buf_addr;
		tr->mbuf_buf_physaddr = (u8*)dst_mb0->buf_physaddr;
		tr->digest = digest;
		tr->digest_offset_from_buf_addr = digest - (u8*)dst_mb0->buf_addr;
		tr->digest_paddr = (u8*)digest_paddr;
	      } else {
		if (lastmb0) {
		    tr->mbuf_buf_addr = lastmb0->buf_addr;
		    tr->mbuf_buf_physaddr = (u8*)lastmb0->buf_physaddr;
		    tr->digest = digest;
		    tr->digest_offset_from_buf_addr = digest - (u8*)lastmb0->buf_addr;
		    tr->digest_paddr = (u8*)digest_paddr;

		    /* Check mvsam driver conditions */
		    tr->mvsam_digest = rte_pktmbuf_mtod_offset(mb0, uint8_t *,
		      (op->sym->aead.data.offset + op->sym->aead.data.length));
		}
	      }
	    }
	}

      if (VLIB_FRAME_SIZE - n_left_to_next)
	{
	  clib_warning ("%s: enqueue %u to next %s (%u)",
			__FUNCTION__, (VLIB_FRAME_SIZE - n_left_to_next),
			vlib_get_next_node (vm, node->node_index,
					    next_index)->name, next_index);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, dpdk_macsec_encrypt_node.index,
				   MACSEC_ENCRYPT_ERROR_RX_PKTS,
				   from_frame->n_vectors);

  crypto_enqueue_ops (vm, cwm, dpdk_macsec_encrypt_node.index,
			  MACSEC_ENCRYPT_ERROR_ENQ_FAIL, numa, 1 /* encrypt */ );

  crypto_free_ops (numa, ops, cwm->ops + from_frame->n_vectors - ops);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (dpdk_macsec_encrypt_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  return dpdk_macsec_encrypt_inline (vm, node, from_frame);
}

VLIB_REGISTER_NODE (dpdk_macsec_encrypt_node) = {
  .name = "dpdk-macsec-encrypt",
  .flags = VLIB_NODE_FLAG_IS_OUTPUT | VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_encrypt_trace,
  .n_errors = ARRAY_LEN (macsec_encrypt_error_strings),
  .error_strings = macsec_encrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes =
    {
      [MACSEC_ENCRYPT_NEXT_DROP] = "error-drop",
    }
};


/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

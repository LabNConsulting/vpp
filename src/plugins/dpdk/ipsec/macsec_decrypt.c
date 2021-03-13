/*
 * macsec_decrypt.c : MACsec Decrypt node using DPDK Cryptodev
 *
 * Copyright (c) 2020, LabN Consulting, L.L.C.
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a opy of the License at:
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
#include <dpdk/buffer.h>
#include <dpdk/ipsec/ipsec.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <iptfs/ipsec_iptfs.h>
#include <vnet/macsec/macsec.h>
#include <vnet/macsec/macsec_format.h>
#include <vnet/ethernet/packet.h>		/* ETHERNET_TYPE_* */

#define foreach_macsec_decrypt_next	       \
_(DROP, "error-drop")			       \
_(ETFS_DECAP, "etfs-decap-rx-macsec")

#define _(v, s) MACSEC_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_macsec_decrypt_next
#undef _
    MACSEC_DECRYPT_N_NEXT,
} macsec_decrypt_next_t;

#define foreach_macsec_decrypt_error				\
 _(RX_PKTS, "MACSEC pkts received")				\
 _(REPLAY, "SA replayed packet")				\
 _(ENQ_FAIL, "Enqueue decrypt failed (queue full)")		\
 _(DISCARD, "Not enough crypto operations")			\
 _(SESSION, "Failed to get crypto session")			\
 _(NOSUP, "Cipher/Auth not supported")				\
 _(NOSA, "No matching SA")					\
 _(INVFLG, "Invalid flags")


typedef enum
{
#define _(sym,str) MACSEC_DECRYPT_ERROR_##sym,
  foreach_macsec_decrypt_error
#undef _
    MACSEC_DECRYPT_N_ERROR,
} macsec_decrypt_error_t;

static char *macsec_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_macsec_decrypt_error
#undef _
};

extern vlib_node_registration_t dpdk_macsec_decrypt_node;

typedef enum
{
    MDTS_NORMAL = 0,
    MDTS_INVFLAG,
    MDTS_NOSA,
    MDTS_RESOURCE,
    MDTS_SESSION,
    MDTS_REPLAY,
} dpdk_macsec_decrypt_trace_status_t;

typedef struct
{
  dpdk_macsec_decrypt_trace_status_t	trace_status;
  ipsec_crypto_alg_t crypto_alg;
  u16	adv;				/* post */
  u16	trunc_size;
  u16	etype;				/* post */
  u32	pkt_len;
  u16	iv_size;
  u8	iv[12];
  u8	packet_data[64];
} macsec_decrypt_trace_t;

static u8 *
format_macsec_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  macsec_decrypt_trace_t *t = va_arg (*args, macsec_decrypt_trace_t *);
  u32 indent = format_get_indent (s);
  char *status;

  switch (t->trace_status) {
        case MDTS_NORMAL:       status = "normal"; break;
        case MDTS_INVFLAG:      status = "invalid flags"; break;
        case MDTS_NOSA:         status = "no matching SA"; break;
        case MDTS_RESOURCE:     status = "no resource"; break;
        case MDTS_SESSION:      status = "no session"; break;
        case MDTS_REPLAY:       status = "replay check failed"; break;
        default:                status = "unknown"; break;
  }

  s = format (s, "status: %s, iv_size %u, trunc_size %u, pkt_len %u\n",
	status,
        t->iv_size, t->trunc_size, t->pkt_len);

    s = format (s, "%Ucipher %U\n",
        format_white_space, indent,
        format_ipsec_crypto_alg, t->crypto_alg);

    s = format (s, "%U%U",
        format_white_space, indent + 2,
        format_macsec_header, t->packet_data);

  return s;
}


always_inline uword
dpdk_macsec_decrypt_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next, next_index, thread_index;
  ipsec_main_t *im = &ipsec_main;
  u32 thread_idx = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res = 0;
  ipsec_sa_t *sa0 = 0;
  crypto_alg_t *cipher_alg = 0;
  struct rte_cryptodev_sym_session *session = 0;
  u32 ret, last_sa_index = ~0;
  u8 numa = rte_socket_id ();
  dpdk_macsec_decrypt_trace_status_t trace_status = MDTS_NORMAL;

  u8 is_aead = 0;
  crypto_worker_main_t *cwm =
    vec_elt_at_index (dcm->workers_main, thread_idx);
  struct rte_crypto_op **ops = cwm->ops;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  ret = crypto_alloc_ops (numa, ops, n_left_from);
  if (ret)
    {
      vlib_node_increment_counter (vm, dpdk_macsec_decrypt_node.index,
				     MACSEC_DECRYPT_ERROR_DISCARD, n_left_from);

      /* safe to assume that all packets received on same interface? */
      MACSEC_INC_SIMPLE_COUNTER(ver_in_pkts_overrun, thread_index,
                                vnet_buffer (vlib_get_buffer (vm, from[0]))->sw_if_index[VLIB_RX],
                                n_left_from);

      /* Discard whole frame */
      vlib_buffer_free (vm, from, n_left_from);
      return n_left_from;
    }

  next_index = MACSEC_DECRYPT_NEXT_DROP;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  clib_error_t		*error;
	  u32			bi0, sa_index0;
	  u8			trunc_size = 0;
	  vlib_buffer_t		*b0;
	  ethernet_header_t	*eh0;
	  struct rte_mbuf	*mb0;
	  struct rte_crypto_op	*op;
	  u16			res_idx;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /* undo ethernet node's advance past ethernet header */
	  vlib_buffer_push_uninit(b0, sizeof(ethernet_header_t));
	  mb0 = rte_mbuf_from_vlib_buffer (b0);
	  eh0 = vlib_buffer_get_current (b0);

	  /* eh0 */
	  CLIB_PREFETCH (eh0, 12 + MACSEC_TAG_WITHSCI_LENGTH, LOAD);
	  /* mb0 */
	  CLIB_PREFETCH (mb0, CLIB_CACHE_LINE_BYTES, STORE);

	  op = ops[0];
	  ops += 1;
	  ASSERT (op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  dpdk_op_priv_t *priv = crypto_op_get_priv (op);
	  dpdk_gcm_cnt_blk *icb = &priv->cb; /* used to build the IV */

	  /* store bi in op private */
	  priv->bi = bi0;
	  priv->encrypt = 0;

	  u16 op_len =
	    sizeof (op[0]) + sizeof (op[0].sym[0]) + sizeof (priv[0]);
	  CLIB_PREFETCH (op, op_len, STORE);

	  /*
	   * Use SCI to look up SA
	   */

	  BVT (clib_bihash_kv)	kv;
	  u8			*pSecTagTciAn = (u8*)eh0 + 14;
	  u8			sci_present;

	  sci_present = *pSecTagTciAn & MACSEC_TCI_FLAG_SC;

	  /*
	   * Does packet contain SCI or must we reconstruct it?
	   */
	  if (sci_present) {
	    /* SCI is present in packet */
	    clib_memcpy(&kv.key, (u8*)eh0 + 20, 8);
	  } else {
	    /*
	     * we must recreate SCI: see ieee 801.1ae 9.5, 9,9
	     */
	    clib_memcpy(&kv.key, (u8*)eh0 + 6, 6);	/* sender's addr */
	    * (((u8*)(&kv.key)) + 6) = 0;
	    if (*pSecTagTciAn & MACSEC_TCI_FLAG_ES) {
		if (*pSecTagTciAn & MACSEC_TCI_FLAG_SCB)
		    * (((u8*)(&kv.key)) + 7) = 0;
		else
		    * (((u8*)(&kv.key)) + 7) = 1;
	    } else {
		/* invalid, drop packet */
		clib_warning ("Invalid TCI flags 0x%x",
			    *pSecTagTciAn & ~MACSEC_TCI_AN_MASK);
		vlib_node_increment_counter (vm,
					     dpdk_macsec_decrypt_node.index,
					     MACSEC_DECRYPT_ERROR_INVFLG, 1);
                MACSEC_INC_SIMPLE_COUNTER(ver_in_pkts_bad_tag, thread_index,
                                          vnet_buffer (b0)->sw_if_index[VLIB_RX], 1);

		to_next[0] = bi0;
		to_next += 1;
		n_left_to_next -= 1;
		trace_status = MDTS_INVFLAG;
		goto trace;
	    }
	  }

	  if (BV(clib_bihash_search)(&macsec_main.decrypt_sa_table, &kv, &kv)) {
	    /* search failed, we have no SA. */
	    vlib_node_increment_counter (vm,
					 dpdk_macsec_decrypt_node.index,
					 MACSEC_DECRYPT_ERROR_NOSA, 1);
            MACSEC_INC_SIMPLE_COUNTER(ver_in_pkts_no_sa, thread_index,
                                      vnet_buffer (b0)->sw_if_index[VLIB_RX], 1);
	    to_next[0] = bi0;
	    to_next += 1;
	    n_left_to_next -= 1;
	    trace_status = MDTS_NOSA;
	    goto trace;
	  }

	  ASSERT((kv.value & 0xffffffff) == kv.value);  /* fit u32 */
	  sa_index0 = kv.value & 0xffffffff;

	  vlib_prefetch_combined_counter (&ipsec_sa_counters,
					  thread_index, sa_index0);

	  if (sa_index0 != last_sa_index)
	    {
	      sa0 = pool_elt_at_index (im->sad, sa_index0);

	      cipher_alg =
		vec_elt_at_index (dcm->cipher_algs, sa0->crypto_alg);

	      is_aead = (cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD);
	      ASSERT(is_aead);

	      res_idx = get_resource (cwm, sa0);

	      if (PREDICT_FALSE (res_idx == (u16) ~ 0))
		{
		  clib_warning ("unsupported SA by thread index %u",
				thread_idx);
		  vlib_node_increment_counter (vm,
						 dpdk_macsec_decrypt_node.index,
						 MACSEC_DECRYPT_ERROR_NOSUP, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  trace_status = MDTS_RESOURCE;
		  goto trace;
		}
	      res = vec_elt_at_index (dcm->resource, res_idx);

	      error = crypto_get_session (&session, sa_index0, res, cwm, 0);
	      if (PREDICT_FALSE (error || !session))
		{
		  clib_warning ("failed to get crypto session");
		  vlib_node_increment_counter (vm,
						 dpdk_macsec_decrypt_node.index,
						 MACSEC_DECRYPT_ERROR_SESSION,
						 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  trace_status = MDTS_SESSION;
		  goto trace;
		}

	      last_sa_index = sa_index0;
	    }

	  /* anti-replay check */
	  u32	pn;
	  int	check;
	  clib_memcpy(&pn, (u8*)eh0 + 16, sizeof(pn));
	  check = ipsec_sa_macsec_anti_replay_check(sa0, clib_net_to_host_u32 (pn));
          if (check == IPSEC_SA_MACSEC_REPLAY_FAIL)
	    {
	      clib_warning ("failed anti-replay check");
	      vlib_node_increment_counter (vm,
	                                   dpdk_macsec_decrypt_node.index,
	                                   MACSEC_DECRYPT_ERROR_REPLAY, 1);
	      MACSEC_INC_SIMPLE_COUNTER(rxsc_in_pkts_late, thread_index,
		                        sa_index0, 1);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      trace_status = MDTS_REPLAY;
	      goto trace;
            }
	  else if (check == IPSEC_SA_MACSEC_REPLAY_DELAYED)
            {
	      MACSEC_INC_SIMPLE_COUNTER(rxsc_in_pkts_delayed, thread_index,
		                        sa_index0, 1);
	    }

	  priv->next = DPDK_CRYPTO_INPUT_NEXT_DECRYPT_MACSEC_POST;

          MACSEC_INC_SIMPLE_COUNTER(ver_in_octets_validated, thread_index,
                                    vnet_buffer (b0)->sw_if_index[VLIB_RX],
                                    b0->current_length);
          MACSEC_INC_SIMPLE_COUNTER(rxsc_in_pkts_ok, thread_index,
                                    vnet_buffer (b0)->sw_if_index[VLIB_RX], 1);

	  /* FIXME multi-seg */
	  vlib_increment_combined_counter
	    (&ipsec_sa_counters, thread_index, sa_index0,
	     1, b0->current_length);

	  res->ops[res->n_ops] = op;
	  res->bi[res->n_ops] = bi0;
	  res->n_ops += 1;

	  /* Convert vlib buffer to mbuf */
	  mb0->data_len = b0->current_length;
	  mb0->pkt_len = b0->current_length;
	  mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

	  trunc_size = cipher_alg->trunc_size;

	  /*
	   * Build AAD
	   */
	  u8 *aad = priv->macsec.aad;
	  if (sci_present) {
	      /* SCI is present in security tag */
	      clib_memcpy_fast(aad, (char *)eh0, 28);
	  } else {
	      clib_memcpy_fast(aad, (char *)eh0, 20);
	      clib_memcpy_fast(aad + 20, (u8*)(&kv.key), 8); /* SCI */
	  }

	  /*
	   * Build IV
	   */

	  /* See ieee 802.1ae section 14.5 */
	  clib_memcpy_fast(icb->raw, aad + 20, 8);	/* SCI */
	  clib_memcpy(icb->raw + 8, (u8*)eh0 + 16, 4);	/* PN */

	  /*
	   * Defer removal of macsec security tag until after
	   * crypto operation
	   */

	  u32 cipher_off, cipher_len;

	  if (sci_present)
	    cipher_off = 12 + MACSEC_TAG_WITHSCI_LENGTH;
	  else
	    cipher_off = 12 + MACSEC_TAG_NOSCI_LENGTH;

	  cipher_len = b0->current_length - cipher_off - trunc_size;

	  u8 *digest = vlib_buffer_get_tail (b0) - trunc_size;
	  u64 digest_paddr =
	    mb0->buf_physaddr + digest - ((u8 *) mb0->buf_addr);

	  crypto_op_setup (is_aead, mb0, NULL, op, session, cipher_off,
			   cipher_len, 0, 0, aad, digest, digest_paddr);

	u32 n_trace;
	trace:
	  /*
	   * TBD: for efficiency, put this in a loop afterward: see
	   * for example plugins/dpdk/device/node.c dpdk_device_input()
	   */
	  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
	  /*if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED)) */
	    {
	      vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 0);
	      macsec_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));

	      tr->trace_status = trace_status;
	      tr->pkt_len = b0->current_length;
	      if (sa0)
		  tr->crypto_alg = sa0->crypto_alg;
	      tr->trunc_size = trunc_size;
	      if (cipher_alg)
		  tr->iv_size = cipher_alg->iv_len;
	      clib_memcpy(tr->iv, icb->raw, sizeof(tr->iv));

	      clib_memcpy_fast (tr->packet_data, vlib_buffer_get_current (b0),
				sizeof (tr->packet_data));
	      vlib_set_trace_count (vm, node, n_trace - 1);
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, dpdk_macsec_decrypt_node.index,
				   MACSEC_DECRYPT_ERROR_RX_PKTS,
				   from_frame->n_vectors);

  crypto_enqueue_ops (vm, cwm, dpdk_macsec_decrypt_node.index,
			  MACSEC_DECRYPT_ERROR_ENQ_FAIL, numa, 0 /* encrypt */ );

  crypto_free_ops (numa, ops, cwm->ops + from_frame->n_vectors - ops);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (dpdk_macsec_decrypt_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return dpdk_macsec_decrypt_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_macsec_decrypt_node) = {
  .name = "dpdk-macsec-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

  .n_errors = ARRAY_LEN(macsec_decrypt_error_strings),
  .error_strings = macsec_decrypt_error_strings,

  .n_next_nodes = MACSEC_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [MACSEC_DECRYPT_NEXT_##s] = n,
    foreach_macsec_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */




/*
 * Decrypt Post Node
 */

#define foreach_macsec_decrypt_post_error	      \
 _(PKTS, "MACSEC post pkts")

typedef enum
{
#define _(sym,str) MACSEC_DECRYPT_POST_ERROR_##sym,
  foreach_macsec_decrypt_post_error
#undef _
    MACSEC_DECRYPT_POST_N_ERROR,
} macsec_decrypt_post_error_t;

static char *macsec_decrypt_post_error_strings[] = {
#define _(sym,string) string,
  foreach_macsec_decrypt_post_error
#undef _
};

extern vlib_node_registration_t dpdk_macsec_decrypt_post_node;



static u8 *
format_macsec_decrypt_post_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  macsec_decrypt_trace_t *t = va_arg (*args, macsec_decrypt_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "adv %u, trunc_size %u, pkt_len %u\n",
        t->adv, t->trunc_size, t->pkt_len);

    s = format (s, "%Ucipher %U\n",
        format_white_space, indent,
        format_ipsec_crypto_alg, t->crypto_alg);

    s = format (s, "%Uetype 0x%x\n",
        format_white_space, indent + 2,
	t->etype);

    s = format (s, "%UEth Payload:\n%U%U",
	format_white_space, indent + 2,
	format_white_space, indent + 2,
	format_hexdump, t->packet_data, sizeof(t->packet_data));

  return s;
}

always_inline uword
dpdk_macsec_decrypt_post_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  u32 thread_index = vm->thread_index;
  ipsec_sa_t *sa0;
  u32 sa_index0 = ~0;
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32			bi0, next0;
	  vlib_buffer_t		*b0 = 0;
	  ethernet_header_t	*eh0;
	  struct rte_mbuf	*mb0;
	  crypto_alg_t		*cipher_alg;
	  u8			trunc_size, is_aead;
	  u16			adv = 0;

	  next0 = MACSEC_DECRYPT_NEXT_DROP;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  eh0 = vlib_buffer_get_current (b0);
	  mb0 = rte_mbuf_from_vlib_buffer (b0);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  to_next[0] = bi0;
	  to_next += 1;

	  cipher_alg = vec_elt_at_index (dcm->cipher_algs, sa0->crypto_alg);

	  is_aead = cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD;
	  ASSERT(is_aead);

	  trunc_size = cipher_alg->trunc_size;

	  u32	pn;
	  clib_memcpy(&pn, (u8*)eh0 + 16, sizeof(pn));
	  ipsec_sa_macsec_anti_replay_advance (sa0,
					clib_net_to_host_u32 (pn));

	  u8			*pSecTagTciAn = (u8*)eh0 + 14;
	  u8			sci_present;
	  u16			etype;

	  sci_present = *pSecTagTciAn & MACSEC_TCI_FLAG_SC;
	  if (sci_present)
	    adv = MACSEC_TAG_WITHSCI_LENGTH;
	  else
	    adv = MACSEC_TAG_NOSCI_LENGTH;

	  /* calculate decrypted pkt len for benefit of trace */
	  u32 pkt_len = b0->current_length - adv - trunc_size;

	  /*
	   * Check etype. Drop if not ETFS.
	   *
	   * Hope we can count on even alignment
	   */
	  etype = clib_net_to_host_u16(*(u16 *)(((u8 *)eh0) + 12 + adv));
	  if (etype != ETHERNET_TYPE_ETFS_EXPERIMENTAL)
		goto trace;

	  /*
	   * ETFS expects start of buffer at start of ethernet payload
	   */
	  vlib_buffer_advance (b0, 12 + adv + 2);


	  /* shorten buffer length to "remove" ICV */
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  b0->current_length -= trunc_size;

	  /* Convert vlib buffer to mbuf */
	  mb0->data_len = b0->current_length;
	  mb0->pkt_len = b0->current_length;
	  mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

	  next0 = MACSEC_DECRYPT_NEXT_ETFS_DECAP;

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

          MACSEC_INC_SIMPLE_COUNTER(ver_in_octets_decrypted, thread_index,
                                    vnet_buffer (b0)->sw_if_index[VLIB_RX],
                                    b0->current_length);

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      macsec_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->etype = etype;
	      tr->adv = adv;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->trunc_size = trunc_size;
	      tr->pkt_len = pkt_len;
	      clib_memcpy_fast(tr->packet_data, vlib_buffer_get_current (b0),
		sizeof(tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, dpdk_macsec_decrypt_post_node.index,
				 MACSEC_DECRYPT_POST_ERROR_PKTS,
				 from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (dpdk_macsec_decrypt_post_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * from_frame)
{
  return dpdk_macsec_decrypt_post_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_macsec_decrypt_post_node) = {
  .name = "dpdk-macsec-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_decrypt_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

  .n_errors = ARRAY_LEN(macsec_decrypt_post_error_strings),
  .error_strings = macsec_decrypt_post_error_strings,

  .n_next_nodes = MACSEC_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [MACSEC_DECRYPT_NEXT_##s] = n,
    foreach_macsec_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
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
#ifndef __DPDK_IPSEC_H__
#define __DPDK_IPSEC_H__

#include <vnet/vnet.h>
#include <vppinfra/cache.h>
#include <vnet/ipsec/ipsec.h>
#include <dpdk/buffer.h>

#undef always_inline
#include <rte_config.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#define DPDK_CRYPTO_N_QUEUE_DESC  (1024 * 4)
#define DPDK_CRYPTO_NB_SESS_OBJS  20000

#define foreach_dpdk_crypto_input_next		\
  _(DROP, "error-drop")				\
  _(IP4_LOOKUP, "ip4-lookup")                   \
  _(IP6_LOOKUP, "ip6-lookup")                   \
  _(INTERFACE_OUTPUT, "interface-output")	\
  _(MIDCHAIN, "adj-midchain-tx")                 \
  _(DECRYPT4_POST, "dpdk-esp4-decrypt-post")     \
  _(DECRYPT6_POST, "dpdk-esp6-decrypt-post")	\
  _(DECRYPT_MACSEC_POST, "dpdk-macsec-decrypt-post")

typedef enum
{
#define _(f,s) DPDK_CRYPTO_INPUT_NEXT_##f,
  foreach_dpdk_crypto_input_next
#undef _
    DPDK_CRYPTO_INPUT_N_NEXT,
} dpdk_crypto_input_next_t;

#define MAX_QP_PER_LCORE 16

typedef struct
{
  union {
    struct {
      u32 salt;
      u32 iv[2];
    };
    u8 raw[12];
  };
  u32 cnt;
} dpdk_gcm_cnt_blk;

typedef struct
{
  u32 next;
  u32 bi;
  u8 encrypt;
    CLIB_ALIGN_MARK (mark0, 16);
  dpdk_gcm_cnt_blk cb;
  union {
      struct {
	  u8 aad[16];
	  u8 icv[32];			/* XXX last 16B in next cache line */
      };
      struct {
	  u8 aad[32];
      } macsec;
  };
} dpdk_op_priv_t;

typedef struct
{
  u16 *resource_idx;
  struct rte_crypto_op **ops;
  u16 cipher_resource_idx[IPSEC_CRYPTO_N_ALG];
  u16 auth_resource_idx[IPSEC_INTEG_N_ALG];
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
} crypto_worker_main_t;

typedef struct
{
  CLIB_ALIGN_MARK (pad, 8);	/* align up to 8 bytes for 32bit builds */
  char *name;
  enum rte_crypto_sym_xform_type type;
  u32 alg;
  u8 key_len;
  u8 iv_len;
  u8 trunc_size;
  u8 boundary;
  u8 disabled;
  u8 resources;
} crypto_alg_t;

typedef struct
{
  u16 *free_resources;
  u16 *used_resources;
  u8 cipher_support[IPSEC_CRYPTO_N_ALG];
  u8 auth_support[IPSEC_INTEG_N_ALG];
  u8 drv_id;
  u8 numa;
  u16 id;
  const char *name;
  u32 max_qp;
  u64 features;
} crypto_dev_t;

typedef struct
{
  const char *name;
  u16 *devs;
} crypto_drv_t;

typedef struct
{
  u16 thread_idx;
  u8 remove;
  u8 drv_id;
  u8 dev_id;
  u8 numa;
  u16 qp_id;
  u16 inflights[2];
  u16 n_ops;
  u16 __unused;
  struct rte_crypto_op *ops[VLIB_FRAME_SIZE];
  u32 bi[VLIB_FRAME_SIZE];
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
} crypto_resource_t;

typedef struct
{
  u64 ts;
  struct rte_cryptodev_sym_session *session;
} crypto_session_disposal_t;

typedef struct
{
  struct rte_cryptodev_sym_session *session;
  u64 dev_mask;
    CLIB_ALIGN_MARK (pad, 16);	/* align up to 16 bytes for 32bit builds */
} crypto_session_by_drv_t;

typedef struct
{
  struct rte_mempool *crypto_op;
  struct rte_mempool *session_h;
  struct rte_mempool **session_drv;
  crypto_session_disposal_t *session_disposal;
  uword *session_by_sa_index;
  u64 crypto_op_get_failed;
  u64 session_h_failed;
  u64 *session_drv_failed;
  crypto_session_by_drv_t *session_by_drv_id_and_sa_index;
  clib_spinlock_t lockp;
  /* Required for vec_validate_aligned */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
} crypto_data_t;

typedef struct
{
  crypto_worker_main_t *workers_main;
  crypto_dev_t *dev;
  crypto_resource_t *resource;
  crypto_alg_t *cipher_algs;
  crypto_alg_t *auth_algs;
  crypto_data_t *data;
  crypto_drv_t *drv;
  u64 session_timeout;		/* nsec */
  u8 enabled;
} dpdk_crypto_main_t;

extern dpdk_crypto_main_t dpdk_crypto_main;

static const u8 pad_data[] =
  { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0 };

void crypto_auto_placement (void);

clib_error_t *create_sym_session (struct rte_cryptodev_sym_session **session,
				  u32 sa_idx, crypto_resource_t * res,
				  crypto_worker_main_t * cwm, u8 is_outbound);

static_always_inline u32
crypto_op_len (void)
{
  const u32 align = 4;
  u32 op_size =
    sizeof (struct rte_crypto_op) + sizeof (struct rte_crypto_sym_op);

  return ((op_size + align - 1) & ~(align - 1)) + sizeof (dpdk_op_priv_t);
}

static_always_inline u32
crypto_op_get_priv_offset (void)
{
  const u32 align = 16;
  u32 offset;

  offset = sizeof (struct rte_crypto_op) + sizeof (struct rte_crypto_sym_op);
  offset = (offset + align - 1) & ~(align - 1);

  return offset;
}

static_always_inline dpdk_op_priv_t *
crypto_op_get_priv (struct rte_crypto_op * op)
{
  return (dpdk_op_priv_t *) (((u8 *) op) + crypto_op_get_priv_offset ());
}


static_always_inline void
add_session_by_drv_and_sa_idx (struct rte_cryptodev_sym_session *session,
			       crypto_data_t * data, u32 drv_id, u32 sa_idx)
{
  crypto_session_by_drv_t *sbd;
  vec_validate_aligned (data->session_by_drv_id_and_sa_index, sa_idx,
			CLIB_CACHE_LINE_BYTES);
  sbd = vec_elt_at_index (data->session_by_drv_id_and_sa_index, sa_idx);
  sbd->dev_mask |= 1L << drv_id;
  sbd->session = session;
}

static_always_inline struct rte_cryptodev_sym_session *
get_session_by_drv_and_sa_idx (crypto_data_t * data, u32 drv_id, u32 sa_idx)
{
  crypto_session_by_drv_t *sess_by_sa;
  if (_vec_len (data->session_by_drv_id_and_sa_index) <= sa_idx)
    return NULL;
  sess_by_sa =
    vec_elt_at_index (data->session_by_drv_id_and_sa_index, sa_idx);
  return (sess_by_sa->dev_mask & (1L << drv_id)) ? sess_by_sa->session : NULL;
}

static_always_inline clib_error_t *
crypto_get_session (struct rte_cryptodev_sym_session ** session,
		    u32 sa_idx,
		    crypto_resource_t * res,
		    crypto_worker_main_t * cwm, u8 is_outbound)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  struct rte_cryptodev_sym_session *sess;

  data = vec_elt_at_index (dcm->data, res->numa);
  sess = get_session_by_drv_and_sa_idx (data, res->drv_id, sa_idx);

  if (PREDICT_FALSE (!sess))
    return create_sym_session (session, sa_idx, res, cwm, is_outbound);

  session[0] = sess;

  return NULL;
}

static_always_inline u16
get_resource (crypto_worker_main_t * cwm, ipsec_sa_t * sa)
{
  u16 cipher_res = cwm->cipher_resource_idx[sa->crypto_alg];
  u16 auth_res = cwm->auth_resource_idx[sa->integ_alg];
  u8 is_aead;

  /* Not allowed to setup SA with no-aead-cipher/NULL or NULL/NULL */

  is_aead = ((sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128) ||
	     (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_192) ||
	     (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_256));

  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_NONE)
    return auth_res;

  if (cipher_res == auth_res)
    return cipher_res;

  if (is_aead)
    return cipher_res;

  return (u16) ~ 0;
}

static_always_inline i32
crypto_alloc_ops (u8 numa, struct rte_crypto_op ** ops, u32 n)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data = vec_elt_at_index (dcm->data, numa);
  i32 ret;

  ret = rte_mempool_get_bulk (data->crypto_op, (void **) ops, n);

  /* *INDENT-OFF* */
  data->crypto_op_get_failed += ! !ret;
  /* *INDENT-ON* */

  return ret;
}

static_always_inline void
crypto_free_ops (u8 numa, struct rte_crypto_op **ops, u32 n)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data = vec_elt_at_index (dcm->data, numa);

  if (!n)
    return;

  rte_mempool_put_bulk (data->crypto_op, (void **) ops, n);
}

static_always_inline void
crypto_enqueue_ops (vlib_main_t * vm, crypto_worker_main_t * cwm,
		    u32 node_index, u32 error, u8 numa, u8 encrypt)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res;
  u16 *res_idx;

  /* *INDENT-OFF* */
  vec_foreach (res_idx, cwm->resource_idx)
    {
      u16 enq, n_ops;
      res = vec_elt_at_index (dcm->resource, res_idx[0]);

      if (!res->n_ops)
	continue;

      n_ops = (DPDK_CRYPTO_N_QUEUE_DESC / 2) - res->inflights[encrypt];
      n_ops = res->n_ops < n_ops ? res->n_ops : n_ops;
      enq = rte_cryptodev_enqueue_burst (res->dev_id, res->qp_id,
					 res->ops, n_ops);
      /* XXX chopps: i've hit this enq == 161 and n_ops == 162 */
      /* XXX chopps: this means it failed to queue or other bad params */
      /* XXX chopps: except the check against 1/2 of the queue should protect us */
      // ASSERT (n_ops == enq);
      if (n_ops != enq)
        {
#if DPDK_ENABLE_CRYPTO_ERROR_ELOG
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (event_enq_unequal) = {
            .format = "crypto-enqueue-ops-bad n_ops %d enq %d encrypt/decrypt %d",
            .format_args = "i4i4i4"
          };
          /* *INDENT-ON* */
          u32 *esd = DPDK_ELOG_CURRENT_THREAD (event_enq_unequal);
          *esd++ = n_ops;
          *esd++ = enq;
          *esd++ = encrypt;
#endif

          clib_warning ("%s: failed to queue all expected packets %u vs %u",
                        __FUNCTION__, enq, n_ops);
        }
      res->inflights[encrypt] += enq;

      if (PREDICT_FALSE (enq < res->n_ops))
	{
          /*
           * Here is where we didn't have enough resources to queue everything
           * Could be failure inside the burst routine, or lack of queue descriptors
           */

          /* Free any source chains that we failed to queue */
          u32 free_bis[res->n_ops - enq], *free_bi = free_bis;
          struct rte_crypto_op **op = &res->ops[enq], **eop = &res->ops[res->n_ops];
          for (; op < eop; op++)
            if (op[0]->sym->m_dst)
              *free_bi++ = vlib_get_buffer_index (vm, vlib_buffer_from_rte_mbuf (op[0]->sym->m_src));

#if DPDK_ENABLE_CRYPTO_ERROR_ELOG
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (event_enq_err) = {
            .format = "crypto-enqueue-ops-err e/dcrypt %d res->n_ops %d enq %d (n_ops %d)",
            .format_args = "i4i4i4i4"
          };
          /* *INDENT-ON* */
          u32 *esd = DPDK_ELOG_CURRENT_THREAD (event_enq_err);
          *esd++ = encrypt;
          *esd++ = res->n_ops;
          *esd++ = enq;
          *esd++ = n_ops;
#endif

          vlib_buffer_free (vm, free_bis, free_bi - free_bis);
          crypto_free_ops (numa, &res->ops[enq], res->n_ops - enq);
          /* Not sure why this *only use* of res->bi below is optimizing for... */
          vlib_buffer_free (vm, &res->bi[enq], res->n_ops - enq);
          vlib_node_increment_counter (vm, node_index, error, res->n_ops - enq);
        }
      res->n_ops = 0;
    }
  /* *INDENT-ON* */
}

static_always_inline void
crypto_set_icb (dpdk_gcm_cnt_blk * icb, u32 salt, u32 seq, u32 seq_hi)
{
  icb->salt = salt;
  icb->iv[0] = seq;
  icb->iv[1] = seq_hi;
}

static_always_inline void
crypto_op_setup (u8 is_aead, struct rte_mbuf *mbsrc0,
		 struct rte_mbuf *mbdst0,
		 struct rte_crypto_op *op, void *session,
		 u32 cipher_off, u32 cipher_len,
		 u32 auth_off, u32 auth_len,
		 u8 * aad, u8 * digest, u64 digest_paddr)
{
  struct rte_crypto_sym_op *sym_op;

  sym_op = (struct rte_crypto_sym_op *) (op + 1);

  /* This can be true for NULL cipher */
  /* if (mbsrc0->nb_segs > 1) */
  /*   ASSERT (mbdst0 != NULL); */

  sym_op->m_src = mbsrc0;
  sym_op->m_dst = mbdst0;
  sym_op->session = session;

  if (is_aead)
    {
      sym_op->aead.data.offset = cipher_off;
      sym_op->aead.data.length = cipher_len;

      sym_op->aead.aad.data = aad;
      sym_op->aead.aad.phys_addr =
	op->phys_addr + (uintptr_t) aad - (uintptr_t) op;

      sym_op->aead.digest.data = digest;
      sym_op->aead.digest.phys_addr = digest_paddr;
    }
  else
    {
      sym_op->cipher.data.offset = cipher_off;
      sym_op->cipher.data.length = cipher_len;

      sym_op->auth.data.offset = auth_off;
      sym_op->auth.data.length = auth_len;

      sym_op->auth.digest.data = digest;
      sym_op->auth.digest.phys_addr = digest_paddr;
    }
}

/*
 * Get the length of the buffer chain, and fixup the mbuf pointers
 */
static inline u16
dpdk_buffer_length_in_chain_fixup (vlib_main_t * vm, vlib_buffer_t * b0,
				   vlib_buffer_t ** lastb0)
{
  int maybe_multiseg;
  u16 len;

  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    {
      maybe_multiseg = 0;
      len = b0->current_length;
    }
  else
    {
      maybe_multiseg = 1;
      if (PREDICT_TRUE (b0->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
	len =
	  b0->current_length + b0->total_length_not_including_first_buffer;
      else
	{
	  /* XXX we never want to hit this in IPTFS */
	  ASSERT (0);
	  len = vlib_buffer_length_in_chain (vm, b0);
	}
    }
  *lastb0 = dpdk_validate_rte_mbuf (vm, b0, maybe_multiseg);
  return len;
}

static inline vlib_buffer_t *
dpdk_ipsec_get_dst_buffer (vlib_main_t * vm, u32 bi, struct rte_mbuf **mb,
		     vlib_buffer_t * src)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  // Too noisy.
  // iptfs_pkt_debug ("%s: buffer %u", __FUNCTION__, bi);

  // Is this right??
  // b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  vnet_buffer (b)->ipsec.sad_index = vnet_buffer (src)->ipsec.sad_index;
  vnet_buffer (b)->sw_if_index[VLIB_RX] =
    vnet_buffer (src)->sw_if_index[VLIB_RX];
  vnet_buffer (b)->sw_if_index[VLIB_TX] =
    vnet_buffer (src)->sw_if_index[VLIB_TX];

  /* Start with no data */
  b->flags |=
    VLIB_BUFFER_TOTAL_LENGTH_VALID | (src->flags & VLIB_BUFFER_IS_TRACED);
  b->current_data = 0;
  b->current_length = 0;

  *mb = rte_mbuf_from_vlib_buffer (b);
  rte_pktmbuf_reset (*mb);
  b->flags |= VLIB_BUFFER_EXT_HDR_VALID;
  return b;
}

#endif /* __DPDK_IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

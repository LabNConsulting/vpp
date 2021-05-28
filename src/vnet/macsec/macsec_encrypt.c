/*
 * macsec_encrypt.c
 *
 * Copyright (c) 2021, LabN Consulting, L.L.C.
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/crypto/crypto.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/macsec/macsec.h>
#include <vnet/macsec/macsec_format.h>

#define MACSEC_ENABLE_SYNC_TRACE	0	/* turn off for speed */

#define foreach_macsec_encrypt_next                \
_(DROP, "error-drop")                              \
_(PENDING, "pending")                              \
_(HANDOFF, "handoff-mac")                          \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) MACSEC_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_macsec_encrypt_next
#undef _
    MACSEC_ENCRYPT_N_NEXT,
} macsec_encrypt_next_t;

#define foreach_macsec_encrypt_error                            \
 _(RX_PKTS, "MACSEC pkts received")                             \
 _(POST_RX_PKTS, "MACSEC-post pkts received")                   \
 _(SEQ_CYCLED, "sequence number cycled (packet dropped)")       \
 _(CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)") \
 _(CRYPTO_QUEUE_FULL, "crypto queue full (packet dropped)")     \
 _(NO_BUFFERS, "no buffers (packet dropped)")                   \

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

typedef enum
{
    METS_NORMAL = 0,
    METS_HANDOFF,	/* hand off to other thread */
    METS_NOBUFS,
    METS_MISSING_CRYPTO_ASYNC_OP_ID,
    METS_ASYNC_PREP_FAIL,
    METS_DSTBUF,
    METS_SYNC_PRE,
    METS_SYNC_POST,
} macsec_encrypt_trace_status_t;

typedef struct
{
    macsec_encrypt_trace_status_t	trace_status;
    u32 sa_index;

    u16	orig_size;
    u16	icv_size;

    u8	ad[28];
    u8	iv[12];
    u8	packet_data[64];
    i16	current_data;
    i32	eh0_off;
    i32	aad_off;
    i32	iv_off;

    u32	src_bi;
    u32	dst_bi;

    ipsec_crypto_alg_t crypto_alg;
    ipsec_integ_alg_t integ_alg;

    u8 op_status;

} macsec_encrypt_trace_t;

typedef struct
{
    u32 next_index;
} macsec_encrypt_post_trace_t;

/* packet trace format function */
static u8 *
format_macsec_encrypt_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    macsec_encrypt_trace_t *t = va_arg (*args, macsec_encrypt_trace_t *);
    u32 indent = format_get_indent (s);
    char *status;

    switch (t->trace_status) {
        case METS_HANDOFF:      status = "handoff"; break;
        case METS_NOBUFS:       status = "no buffers"; break;
        case METS_MISSING_CRYPTO_ASYNC_OP_ID: status = "no crypto async op id"; break;
        case METS_ASYNC_PREP_FAIL: status = "async prep fail"; break;
        case METS_DSTBUF:       status = "no dstbuf"; break;
	case METS_NORMAL:       status = "normal"; break;
	case METS_SYNC_PRE:     status = "sync pre"; break;
	case METS_SYNC_POST:    status = "sync post"; break;
        default:                status = "unknown"; break;
    }

    if ((t->trace_status == METS_HANDOFF) ||
	(t->trace_status == METS_NOBUFS)) {
	s = format(s, "sa %u, status: %s\n", t->sa_index, status);
	return s;
    }
    if ((t->trace_status == METS_SYNC_POST) ||
	(t->trace_status == METS_SYNC_PRE)) {
	s = format(s, " IV: %U\n",
	  format_hexdump, t->iv, sizeof(t->iv));

	s = format(s, "%UAAD: %U\n",
	  format_white_space, indent,
	  format_hexdump, t->ad, sizeof(t->ad));

	s = format(s, "%Ucrypto-op info: status %u, current_data %d\n",
	    format_white_space, indent,
	    t->op_status, t->current_data);

	s = format(s, "%UEH0: %U\n",
	  format_white_space, indent,
	  format_hexdump, t->packet_data, sizeof(t->packet_data));

	s = format(s, "%Ustatus: %s\n",
	    format_white_space, indent,
	    status);
	return s;
    }

    /* already indented at this point */
    s = format(s, " IV: %U\n",
      format_hexdump, t->iv, sizeof(t->iv));

    s = format(s, "%UAAD: %U\n",
      format_white_space, indent,
      format_hexdump, t->ad, sizeof(t->ad));

    s = format(s, "%U EH: %U\n",
      format_white_space, indent,
      format_ethernet_header, t->packet_data);

    s = format(s, "%UEH0: %U\n",
      format_white_space, indent,
      format_hexdump, t->packet_data, sizeof(t->packet_data));

    s = format (s,
	"%Ustatus: %s, sa_idx %u, icv_size %u, current_data %d, iv_off %d, aad_off %d, eh0_off %d, src_bi %u, dst_bi %u\n",
	format_white_space, indent,
        status, t->sa_index, t->icv_size,
	t->current_data, t->iv_off, t->aad_off, t->eh0_off,
	t->src_bi, t->dst_bi);

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
        /* OP has been set up. Display saved values */
	/* TBD */
	s = format(s, "%Ucrypto-op info: status %u, TBD\n",
	    format_white_space, indent,
	    t->op_status);
    }

    return s;
}

static u8 *
format_macsec_post_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  macsec_encrypt_post_trace_t *t = va_arg (*args, macsec_encrypt_post_trace_t *);

  s = format (s, "macsec-post: next node index %u", t->next_index);
  return s;
}

static_always_inline u8 *
macsec_add_icv(
    vlib_main_t		*vm,
    vlib_buffer_t	**last,
    u8			icv_sz,
    u16			buffer_data_size,
    uword		total_len)
{
    u8 *icv = NULL;

    if (last[0]->current_length + icv_sz > buffer_data_size) {
	u32 tmp_bi = 0;

	if (vlib_buffer_alloc (vm, &tmp_bi, 1) != 1)
	    goto done;

	vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
	last[0]->next_buffer = tmp_bi;
	last[0]->flags |= VLIB_BUFFER_NEXT_PRESENT;
	last[0] = tmp;
    }

    icv = vlib_buffer_put_uninit(last[0], icv_sz);

done:
    return icv;
}

/*
 * Synchronous mode
 */
static_always_inline void
macsec_process_chained_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vnet_crypto_op_t * ops, vlib_buffer_t * b[],
			 u16 * nexts, vnet_crypto_op_chunk_t * chunks,
			 u16 drop_next)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_chained_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 bi = op->user_data;
	  b[bi]->error = node->errors[MACSEC_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	  macsec_encrypt_post_data(b[bi])->error = op->status;
	  nexts[bi] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

/*
 * Synchronous mode
 */
static_always_inline void
macsec_process_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vnet_crypto_op_t * ops, vlib_buffer_t * b[], u16 * nexts,
		 u16 drop_next)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

#if MACSEC_ENABLE_SYNC_TRACE
    for (uint i = 0; i < n_ops; ++i) {
	if (PREDICT_FALSE (b[i]->flags & VLIB_BUFFER_IS_TRACED)) {
	    macsec_encrypt_trace_t *tr = vlib_add_trace (vm, node, b[i],
						      sizeof (*tr));
	    tr->trace_status = METS_SYNC_PRE;
	    tr->op_status = ops[i].status;

	    tr->current_data = b[i]->current_data;

	    clib_memcpy_fast(tr->packet_data,
		vlib_buffer_get_current(b[i]), sizeof (tr->packet_data));
	    clib_memcpy_fast(tr->iv,
		vlib_buffer_get_current(b[i]) - 40, sizeof (tr->iv));
	    clib_memcpy_fast(tr->ad,
		vlib_buffer_get_current(b[i]) - 28, sizeof (tr->ad));
	}
    }
#endif

  n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 bi = op->user_data;
	  b[bi]->error = node->errors[MACSEC_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	  macsec_encrypt_post_data(b[bi])->error = op->status;
	  nexts[bi] = drop_next;
	  n_fail--;
	}
      op++;
    }

#if MACSEC_ENABLE_SYNC_TRACE
    for (uint i = 0; i < n_ops; ++i) {
	if (PREDICT_FALSE (b[i]->flags & VLIB_BUFFER_IS_TRACED)) {
	    macsec_encrypt_trace_t *tr = vlib_add_trace (vm, node, b[i],
						      sizeof (*tr));
	    tr->trace_status = METS_SYNC_POST;
	    tr->op_status = ops[i].status;

	    tr->current_data = b[i]->current_data;

	    clib_memcpy_fast(tr->packet_data,
		vlib_buffer_get_current(b[i]), sizeof (tr->packet_data));
	    clib_memcpy_fast(tr->iv,
		vlib_buffer_get_current(b[i]) - 40, sizeof (tr->iv));
	    clib_memcpy_fast(tr->ad,
		vlib_buffer_get_current(b[i]) - 28, sizeof (tr->ad));
	}
    }
#endif
}

typedef struct
{
  u64 sci;
  u32 pn;
} __clib_packed macsec_gcm_nonce_t;

STATIC_ASSERT_SIZEOF (macsec_gcm_nonce_t, 12);

static_always_inline u32
macsec_encrypt_chain_crypto(
    vlib_main_t			*vm,
    macsec_per_thread_data_t	*ptd,
    vlib_buffer_t		*b,
    vlib_buffer_t		*lb,
    u8				icv_sz,
    u8				*start,
    u32				start_len,
    u16				*n_ch)
{
    vnet_crypto_op_chunk_t *ch;
    vlib_buffer_t *cb = b;
    u32 n_chunks = 1;
    u32 total_len;

    vec_add2 (ptd->chunks, ch, 1);
    total_len = ch->len = start_len;
    ch->src = ch->dst = start;
    cb = vlib_get_buffer (vm, cb->next_buffer);

    while (1) {
	vec_add2 (ptd->chunks, ch, 1);
	n_chunks += 1;
	if (lb == cb)
	    total_len += ch->len = cb->current_length - icv_sz;
	else
	    total_len += ch->len = cb->current_length;
	ch->src = ch->dst = vlib_buffer_get_current (cb);

	if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	    break;

	cb = vlib_get_buffer (vm, cb->next_buffer);
    }

    if (n_ch)
	*n_ch = n_chunks;

  return total_len;
}

always_inline void
macsec_prepare_sync_op(
    vlib_main_t			*vm,
    macsec_per_thread_data_t	*ptd,
    vnet_crypto_op_t		**crypto_ops,
    vnet_crypto_op_t		**integ_ops,
    ipsec_sa_t			*sa0,
    u8				*encrypt_start,	/* part to be encrypted */
    u16				encrypt_len,	/* NOT incl ICV */
    u8				*aad,
    u8				aad_sz,
    u8				*iv,
    u8				*icv,
    u8				icv_sz,
    vlib_buffer_t		**bufs,
    vlib_buffer_t		**b,
    vlib_buffer_t		*lb)
{
    /*
     * macsec crypto op only (encrypts and generates icv in one op)
     */
    ASSERT(sa0->crypto_enc_op_id);
    ASSERT(!sa0->integ_op_id);

    vnet_crypto_op_t *op;

    vec_add2_aligned (crypto_ops[0], op, 1, CLIB_CACHE_LINE_BYTES);
    vnet_crypto_op_init (op, sa0->crypto_enc_op_id);

    op->src = op->dst = encrypt_start;
    op->key_index = sa0->crypto_key_index;
    op->len = encrypt_len;
    op->user_data = b - bufs;	/* save index of buffer in array */

    op->aad = aad;
    op->aad_len = aad_sz;

    op->tag = icv;
    op->tag_len = icv_sz;

    op->iv = iv;

    if (lb != b[0]) {
	/* is chained */
	op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	op->chunk_index = vec_len (ptd->chunks);
	op->tag = NULL;
	macsec_encrypt_chain_crypto(vm, ptd, b[0], lb, icv_sz,
	    encrypt_start, encrypt_len, &op->n_chunks);
    }
}

static_always_inline int
macsec_prepare_async_frame(
    vlib_main_t			*vm,
    macsec_per_thread_data_t	*ptd,
    vnet_crypto_async_frame_t	**async_frame,
    ipsec_sa_t			*sa,
    vlib_buffer_t		*b,
    u8				*payload,
    u32				payload_len,	/* this INCLUDES ICV */
    u8				*aad,		/* new: start of aad */
    u8				*iv,		/* new: start of iv */
    u8				icv_sz,
    u32				bi,
    u16				*next,
    u16				async_next,
    vlib_buffer_t		*lb)
{
    macsec_encrypt_post_data_t *post = macsec_encrypt_post_data (b);
    u8 *tag;
    u8 flag = 0;
    u32 key_index;
    i16 crypto_start_offset, integ_start_offset = 0;
    u16 crypto_total_len, integ_total_len;

    post->next_index = next[0];
    next[0] = MACSEC_ENCRYPT_NEXT_PENDING;

    /* crypto */
    crypto_start_offset = payload - b->data;
    crypto_total_len = integ_total_len = payload_len - icv_sz;
    tag = payload + crypto_total_len;

    key_index = sa->crypto_key_index;

    if (lb != b) {
	/* chain */
	flag |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	tag = vlib_buffer_get_tail (lb) - icv_sz;
	crypto_total_len = macsec_encrypt_chain_crypto (vm, ptd, b, lb,
						     icv_sz, payload,
						     payload_len, 0);
    }

    return vnet_crypto_async_add_to_frame(
	vm, async_frame, key_index,
	crypto_total_len,
	integ_total_len - crypto_total_len,
	crypto_start_offset,
	integ_start_offset, bi, async_next,
	iv, tag, aad, flag);
}

/* when submitting a frame is failed, drop all buffers in the frame */
static_always_inline void
macsec_async_recycle_failed_submit (vnet_crypto_async_frame_t * f,
				 vlib_buffer_t ** b, u16 * next,
				 u16 drop_next)
{
  u32 n_drop = f->n_elts;
  while (--n_drop)
    {
      vlib_buffer_t *cb;

      cb = (b - n_drop)[0];
      cb->error = MACSEC_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR;
      macsec_encrypt_post_data(cb)->error = 254;
      (next - n_drop)[0] = drop_next;
    }
  vnet_crypto_async_reset_frame (f);
}

always_inline uword
macsec_encrypt_inline(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_frame_t	*frame,
    u16			async_next)
{
    ipsec_main_t	*im = &ipsec_main;
    macsec_main_t	*mm = &macsec_main;
    macsec_per_thread_data_t *ptd = vec_elt_at_index(mm->ptd, vm->thread_index);
    u32			*from = vlib_frame_vector_args (frame);
    u32			n_left = frame->n_vectors;
    vlib_buffer_t	*bufs[VLIB_FRAME_SIZE], **b = bufs;
    u16			nexts[VLIB_FRAME_SIZE], *next = nexts;
    u32			thread_index = vm->thread_index;
    u16			buffer_data_size = vlib_buffer_get_default_data_size (vm);
    u32			current_sa_index = ~0, current_sa_packets = 0;
    u32			current_sa_bytes = 0;
    u8			icv_sz = 0;
    ipsec_sa_t		*sa0 = 0;
    vlib_buffer_t	*lb;

    vnet_crypto_op_t	**crypto_ops = &ptd->crypto_ops;
    vnet_crypto_op_t	**integ_ops = &ptd->integ_ops;

    int			is_async = im->async_mode;
    vnet_crypto_async_frame_t *async_frame = 0;
    vnet_crypto_async_op_id_t last_async_op = ~0;

    u16			drop_next = MACSEC_ENCRYPT_NEXT_DROP;

    vlib_get_buffers (vm, from, b, n_left);
    if (!is_async) {
	vec_reset_length (ptd->crypto_ops);
	vec_reset_length (ptd->integ_ops);
	vec_reset_length (ptd->chained_crypto_ops);
	vec_reset_length (ptd->chained_integ_ops);
    }
    vec_reset_length (ptd->chunks);

#if 0
    clib_warning ("%s: esp_encrypt %u is_tun %u", __FUNCTION__,
		frame->n_vectors, is_tun);
#endif

    while (n_left > 0) {
	u32 sa_index0;
	u8 *payload;
	u16 payload_len, payload_len_total, n_bufs;
	u16 len_orig = 0;
	u8 *aad = NULL;
	u8 *iv = NULL;
	u8 *eh0 = NULL;
	u8 *eh0_orig = NULL;
	macsec_encrypt_trace_status_t	trace_status = METS_NORMAL;

	if (n_left > 2) {
	    u8 *p;
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    p = vlib_buffer_get_current (b[1]);
	    CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	    p -= CLIB_CACHE_LINE_BYTES;
	    CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

	/* we overload the ipsec sa index for macsec */
	sa_index0 = vnet_buffer (b[0])->ipsec.sad_index;

	if (sa_index0 != current_sa_index) {
	    if (current_sa_packets)
	      vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					       current_sa_index,
					       current_sa_packets,
					       current_sa_bytes);
	    current_sa_packets = current_sa_bytes = 0;

	    ASSERT (!pool_is_free_index (im->sad, sa_index0));
	    sa0 = pool_elt_at_index (im->sad, sa_index0);
	    current_sa_index = sa_index0;

	    icv_sz = sa0->integ_icv_size;

	    /* submit frame when op_id is different then the old one */
	    if (is_async && sa0->crypto_async_enc_op_id != last_async_op) {
		if (async_frame && async_frame->n_elts) {
		    if (vnet_crypto_async_submit_open_frame (vm, async_frame)
			< 0)
		      macsec_async_recycle_failed_submit (async_frame, b,
						       next, drop_next);
		}
		async_frame =
		  vnet_crypto_async_get_frame (vm, sa0->crypto_async_enc_op_id);
		last_async_op = sa0->crypto_async_enc_op_id;
	    }
	}

	if (PREDICT_FALSE (~0 == sa0->encrypt_thread_index)) {
	    /* this is the first packet to use this SA, claim the SA
	     * for this thread. this could happen simultaneously on
	     * another thread */
	    clib_atomic_cmp_and_swap (&sa0->encrypt_thread_index, ~0,
				      ipsec_sa_assign_thread (thread_index));
	}

	if (PREDICT_TRUE (thread_index != sa0->encrypt_thread_index)) {
	    next[0] = MACSEC_ENCRYPT_NEXT_HANDOFF;
	    trace_status = METS_HANDOFF;
	    goto trace;
	}

	lb = b[0];
	n_bufs = vlib_buffer_chain_linearize (vm, b[0]);
	if (n_bufs == 0) {
	    b[0]->error = node->errors[MACSEC_ENCRYPT_ERROR_NO_BUFFERS];
	    next[0] = drop_next;
	    trace_status = METS_NOBUFS;
	    goto trace;
	}

	if (n_bufs > 1) {
	    /* find last buffer in the chain */
	    while (lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	      lb = vlib_get_buffer (vm, lb->next_buffer);
	}

	/*
	 * Set up packet buffer for macsec.
	 *
	 * 1. Insert 8 octet macsec header between original src
	 *    addr and original etype. This operation means:
	 *    - move start-of-packet mark back 8 bytes
	 *    - copy 12 bytes from original start-of-packet to new
	 *      start-of-packet (overlappig copy)
	 *    - build 8-byte macsec header
	 *
	 * 2. Use a scratch area in the unused prepend area ahead
	 *    of the start-of-packet to build the AAD and IV.
	 *
	 *    AAD = 28 bytes
	 *    IV = 12 bytes
	 *
	 * 3. The 12-byte src+dst addr + 8-byte macsec header (i.e., the
	 *    first 20 bytes of the packet we are building) is actually
	 *    identical to the first 20 bytes of the AAD. So, the
	 *    sequence of operations will be:
	 *
	 *      - shift start-of-packet back 8 bytes
	 *      - set AAD pointer into scratch area 28 bytes before
	 *        start-of-packet
	 *      - set IV pointer into scratch area 16 bytes before AAD
	 *
	 *      - build AAD in full
	 *      - copy first 20 bytes of AAD to start-of-packet
	 *
	 *      - set up crypto operations
	 */

	/*
	 * Note that the src and dst addresses of the original packet have
	 * already been set to the tunnel endpoints by ETFS. If non-etfs
	 * use macsec, we will need to change code here to get correct
	 * src/dst addresses.
	 */

	eh0_orig = vlib_buffer_get_current (b[0]);
	len_orig = vlib_buffer_length_in_chain(vm, b[0]);

	payload = eh0_orig + (6+6);	/* assumes contiguous */
	payload_len = b[0]->current_length - (6+6);
	payload_len_total = len_orig - (6+6);

	eh0 = vlib_buffer_push_uninit(b[0], MACSEC_TAG_NOSCI_LENGTH);
	aad = vlib_buffer_push_uninit(b[0], MACSEC_AAD_LENGTH);	/* assert spc */
	iv = vlib_buffer_push_uninit(b[0], 12);			/* assert spc */
	vlib_buffer_advance(b[0], MACSEC_AAD_LENGTH+12);	/* restore */

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

	/*
	 * Hope we can count on at least even alignment below, otherwise
	 * fix the *(u16*) writes.
	 */

	/*
	 * Set up AAD
	 */
	clib_memcpy_fast(aad, (char *)eh0_orig, 12); /* dst, src ethaddr */
	*(u16 *)(aad + 12) = clib_host_to_net_u16(MACSEC_ETYPE);
	aad[14] = MACSEC_TCI_AN_DEFAULT;
	if (payload_len < 48) /* short length */
	    aad[15] = payload_len_total & 0x3f;
	else
	    aad[15] = 0;
	u32 packet_number = clib_host_to_net_u32(ipsec_sa_macsec_next_pn(sa0));
	clib_memcpy(aad + 16, (char *)&packet_number, sizeof(u32));
	/* src ethernet addr: same issue as noted above vis a vis etfs */
	clib_memcpy(aad + 20, ((char *)eh0_orig) + 6, 6);

	/* ES=1,SCB=0 => port 1 */
	*(u16 *)(aad + 26) = clib_host_to_net_u16(0x0001);

	/*
	 * set up IV
	 * same contents as last 12 bytes of AAD, but different order (sigh),
	 */
	clib_memcpy_fast(iv, aad + 20, 8);	/* SCI */
	clib_memcpy(iv + 8, aad + 16, 4);	/* PN */

	/*
	 * Write packet header at new earlier offset. Happens to be
	 * same as first 20 bytes of AAD.
	 */
	clib_memcpy_fast(eh0, aad, (6 + 6) + MACSEC_TAG_NOSCI_LENGTH);

	/*
	 * Get pointer to target location for ICV that will be written
	 * by integrity operation. This location is immediately at the
	 * end of the packet.
	 */

	/*
	 * append ICV area
	 *
	 * TBD maybe do this earlier so payload length numbers above
	 * will include icv (and macsec header "short length, etc. are
	 * correct.
	 *
	 * some notes:
	 * ICV area must be contiguous. esp_add_footer_and_icv() ensures
	 * this by chaining another buffer on the end if there is not
	 * enough room in the last packet buffer
	 */
	u8 *icv = macsec_add_icv(vm, &lb, icv_sz, buffer_data_size,
	    vlib_buffer_length_in_chain(vm, b[0]));

	if (!icv) {
	    b[0]->error = node->errors[MACSEC_ENCRYPT_ERROR_NO_BUFFERS];
	    next[0] = drop_next;
	    trace_status = METS_NOBUFS;
	    goto trace;
	}
	b[0]->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

	next[0] = MACSEC_ENCRYPT_NEXT_INTERFACE_OUTPUT;

	if (lb != b[0]) {
	    crypto_ops = &ptd->chained_crypto_ops;
	    integ_ops = &ptd->chained_integ_ops;
	} else {
	    crypto_ops = &ptd->crypto_ops;
	    integ_ops = &ptd->integ_ops;
	}

	if (is_async) {
	    if (PREDICT_FALSE (sa0->crypto_async_enc_op_id == 0)) {
		trace_status = METS_MISSING_CRYPTO_ASYNC_OP_ID;
		goto trace;
	    }

	    if (macsec_prepare_async_frame(
		vm, ptd, &async_frame, sa0, b[0],
		payload, payload_len,
		aad, iv,
		icv_sz,
		from[b - bufs], next, async_next, lb)) {

		macsec_async_recycle_failed_submit (async_frame, b, next,
						 drop_next);
		trace_status = METS_ASYNC_PREP_FAIL;
		goto trace;
	    }
	} else {
	    macsec_prepare_sync_op(
	      vm, ptd, crypto_ops, integ_ops, sa0,
	      payload, payload_len,
	      aad, MACSEC_AAD_LENGTH,
	      iv,
	      icv, icv_sz,
	      bufs, b, lb);
	}

	current_sa_packets += 1;
	current_sa_bytes += payload_len_total;

	/* There is some chance that this will not be encrypted for lack of
	 * resources, but the management model doesn't distinguish . . .
	 * Also, we always increment the "encrypted" counter and never the
	 * "protected" counter since GMAC is not supported.  Make adjustments
	 * here if that changes.
	 */
	MACSEC_INC_COMBINED_COUNTER(txsc_out_pkts_encrypted, thread_index,
				    vnet_buffer (b[0])->sw_if_index[VLIB_TX],
				    1,  b[0]->current_length);


trace:
	if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
	    macsec_encrypt_trace_t *tr = vlib_add_trace (vm, node, b[0],
						      sizeof (*tr));
	    tr->trace_status = trace_status;
	    tr->sa_index = sa_index0;
	    tr->orig_size = len_orig;
	    tr->icv_size = icv_sz;

	    if (aad)
		clib_memcpy_fast(tr->ad, aad, sizeof (tr->ad));
	    if (iv)
		clib_memcpy_fast(tr->iv, iv, sizeof (tr->iv));
	    if (eh0)
		clib_memcpy_fast(tr->packet_data, eh0, sizeof (tr->packet_data));

	    tr->current_data = b[0]->current_data;
	    tr->eh0_off = eh0 - (u8*)vlib_buffer_get_current(b[0]);
	    tr->aad_off = aad - (u8*)vlib_buffer_get_current(b[0]);
	    tr->iv_off = iv - (u8*)vlib_buffer_get_current(b[0]);

	    tr->op_status = macsec_encrypt_post_data(b[0])->error;
	    tr->crypto_alg = sa0->crypto_alg;
	    tr->integ_alg = sa0->integ_alg;
	}
	/* next */
	n_left -= 1;
	next += 1;
	b += 1;
    }

    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				     current_sa_index, current_sa_packets,
				     current_sa_bytes);
    if (!is_async) {
	macsec_process_ops (vm, node, ptd->crypto_ops, bufs, nexts, drop_next);
	macsec_process_chained_ops (vm, node, ptd->chained_crypto_ops, bufs, nexts,
				 ptd->chunks, drop_next);
/* TBD do post-encrypt trace here or in process functions above */
    } else if (async_frame && async_frame->n_elts) {
	int ret;

	ret = vnet_crypto_async_submit_open_frame (vm, async_frame);
	if (ret < 0) {
	  macsec_async_recycle_failed_submit (async_frame, b, next, drop_next);
	}
    }

    vlib_node_increment_counter (vm, node->node_index,
			       MACSEC_ENCRYPT_ERROR_RX_PKTS, frame->n_vectors);

#if 0
    if (frame->n_vectors) {
	clib_warning ("%s: enqueue %u to next %s (%u) is_tun %u", __FUNCTION__,
		      frame->n_vectors,
		      vlib_get_next_node (vm, node->node_index, nexts[0])->name,
		      nexts[0], is_tun);
    }
#endif

    vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
    return frame->n_vectors;
}

always_inline uword
macsec_encrypt_post_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, b, n_left);

  if (n_left >= 4)
    {
      vlib_prefetch_buffer_header (b[0], LOAD);
      vlib_prefetch_buffer_header (b[1], LOAD);
      vlib_prefetch_buffer_header (b[2], LOAD);
      vlib_prefetch_buffer_header (b[3], LOAD);
    }

  while (n_left > 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      next[0] = (macsec_post_data (b[0]))->next_index;
      next[1] = (macsec_post_data (b[1]))->next_index;
      next[2] = (macsec_post_data (b[2]))->next_index;
      next[3] = (macsec_post_data (b[3]))->next_index;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      macsec_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[0],
							     sizeof (*tr));
	      tr->next_index = next[0];
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      macsec_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[1],
							     sizeof (*tr));
	      tr->next_index = next[1];
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      macsec_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[2],
							     sizeof (*tr));
	      tr->next_index = next[2];
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      macsec_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[3],
							     sizeof (*tr));
	      tr->next_index = next[3];
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      next[0] = (macsec_post_data (b[0]))->next_index;
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  macsec_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[0],
							 sizeof (*tr));
	  tr->next_index = next[0];
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       MACSEC_ENCRYPT_ERROR_POST_RX_PKTS,
			       frame->n_vectors);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (macsec_encrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
    return macsec_encrypt_inline(
	vm,
	node,
	from_frame,
	macsec_main.encrypt_async_post_next);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (macsec_encrypt_node) = {
  .name = "macsec-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(macsec_encrypt_error_strings),
  .error_strings = macsec_encrypt_error_strings,

  .n_next_nodes = MACSEC_ENCRYPT_N_NEXT,
  .next_nodes = {
    [MACSEC_ENCRYPT_NEXT_DROP] = "error-drop",
    [MACSEC_ENCRYPT_NEXT_HANDOFF] = "macsec-encrypt-handoff",
    [MACSEC_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "interface-output",
    [MACSEC_ENCRYPT_NEXT_PENDING] = "macsec-encrypt-pending",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (macsec_encrypt_post_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return macsec_encrypt_post_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (macsec_encrypt_post_node) = {
  .name = "macsec-encrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_post_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "macsec-encrypt",

  .n_errors = ARRAY_LEN(macsec_encrypt_error_strings),
  .error_strings = macsec_encrypt_error_strings,
};
/* *INDENT-ON* */

#if 0

typedef struct
{
  u32 sa_index;
} macsec_no_crypto_trace_t;

static u8 *
format_macsec_no_crypto_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  macsec_no_crypto_trace_t *t = va_arg (*args, macsec_no_crypto_trace_t *);

  s = format (s, "esp-no-crypto: sa-index %u", t->sa_index);

  return s;
}

enum
{
  MACSEC_NO_CRYPTO_NEXT_DROP,
  MACSEC_NO_CRYPTO_N_NEXT,
};

enum
{
  MACSEC_NO_CRYPTO_ERROR_RX_PKTS,
};

static char *macsec_no_crypto_error_strings[] = {
  "Outbound ESP packets received",
};

always_inline uword
macsec_no_crypto_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, b, n_left);

  while (n_left > 0)
    {
      u32 sa_index0;

      /* packets are always going to be dropped, but get the sa_index */
      sa_index0 = ipsec_tun_protect_get_sa_out
	(vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  macsec_no_crypto_trace_t *tr = vlib_add_trace (vm, node, b[0],
						      sizeof (*tr));
	  tr->sa_index = sa_index0;
	}

      n_left -= 1;
      b += 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       MACSEC_NO_CRYPTO_ERROR_RX_PKTS, frame->n_vectors);

  vlib_buffer_enqueue_to_single_next (vm, node, from,
				      MACSEC_NO_CRYPTO_NEXT_DROP,
				      frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (esp4_no_crypto_tun_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return macsec_no_crypto_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_no_crypto_tun_node) =
{
  .name = "esp4-no-crypto",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_no_crypto_trace,
  .n_errors = ARRAY_LEN(macsec_no_crypto_error_strings),
  .error_strings = macsec_no_crypto_error_strings,
  .n_next_nodes = MACSEC_NO_CRYPTO_N_NEXT,
  .next_nodes = {
    [MACSEC_NO_CRYPTO_NEXT_DROP] = "ip4-drop",
  },
};

#endif /* 0 */

VLIB_NODE_FN (macsec_encrypt_pending_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (macsec_encrypt_pending_node) = {
  .name = "macsec-encrypt-pending",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 0
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

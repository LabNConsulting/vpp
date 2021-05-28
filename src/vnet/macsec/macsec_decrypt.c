/*
 * macsec_decrypt.c
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
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/macsec/macsec.h>

#define foreach_macsec_decrypt_next             \
_(DROP, "error-drop")                           \
_(ETFS_DECAP, "etfs-decap-rx-macsec")           \
_(HANDOFF, "handoff")				\
_(PENDING, "pending")

#define _(v, s) MACSEC_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_macsec_decrypt_next
#undef _
    MACSEC_DECRYPT_N_NEXT,
} macsec_decrypt_next_t;

#define foreach_macsec_decrypt_post_next               \
_(DROP, "error-drop")                                  \
_(ETFS_DECAP, "etfs-decap-rx-macsec")

#define _(v, s) MACSEC_DECRYPT_POST_NEXT_##v,
typedef enum
{
  foreach_macsec_decrypt_post_next
#undef _
    MACSEC_DECRYPT_POST_N_NEXT,
} macsec_decrypt_post_next_t;

#define foreach_macsec_decrypt_error                            \
 _(RX_PKTS, "ESP pkts received")                                \
 _(RX_POST_PKTS, "ESP-POST pkts received")                      \
 _(DECRYPTION_FAILED, "ESP decryption failed")                  \
 _(INVFLAG, "Invalid TCI flags")                                \
 _(NOSA, "No matching SA")                                      \
 _(INTEG_ERROR, "Integrity check failed")                       \
 _(CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)") \
 _(REPLAY, "SA replayed packet")                                \
 _(RUNT, "undersized packet")                                   \
 _(NO_BUFFERS, "no buffers (packet dropped)")                   \
 _(OVERSIZED_HEADER, "buffer with oversized header (dropped)")  \
 _(NO_TAIL_SPACE, "no enough buffer tail space (dropped)")      \
 _(TUN_NO_PROTO, "no tunnel protocol")                          \
 _(UNSUP_PAYLOAD, "unsupported payload")                        \


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

typedef enum
{
    MACSEC_TRACE_STEP_PRE,
    MACSEC_TRACE_STEP_POST,
} macsec_trace_step_t;

typedef struct
{
  u32			pn;
  u32			sa_pn;
  u16			etype;	/* only valid for POST */
  u16			next;
  ethernet_header_t	eh;
  macsec_trace_step_t	step;

  ipsec_crypto_alg_t	crypto_alg;
  ipsec_integ_alg_t	integ_alg;
  bool			sci_present;
  u64			kv_key;
} macsec_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_macsec_decrypt_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    macsec_decrypt_trace_t *t = va_arg (*args, macsec_decrypt_trace_t *);

    s = format (s,
	"macsec: crypto %U, integrity %U, pkt-pn %d, sa-pn %u",
	format_ipsec_crypto_alg, t->crypto_alg,
	format_ipsec_integ_alg, t->integ_alg,
	t->pn, t->sa_pn);
    s = format(s, "  sci_present %d, kv.key: 0x%016lx\n",
	t->sci_present,
	t->kv_key);
    s = format(s, "EH: %U\n", format_ethernet_header, &t->eh);
    return s;
}

static_always_inline void
macsec_process_ops(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vnet_crypto_op_t	*ops,
    vlib_buffer_t	*b[],
    u16			*nexts,
    int			e)
{
    vnet_crypto_op_t *op = ops;
    u32 n_fail, n_ops = vec_len (ops);

    if (n_ops == 0)
	return;

    n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

    if (n_fail > 0) {
	u32 thread_index = vm->thread_index;
	MACSEC_INC_SIMPLE_COUNTER(ver_in_pkts_overrun, thread_index,
	    vnet_buffer (b[0])->sw_if_index[VLIB_RX], n_fail);
    }

    while (n_fail) {
	ASSERT (op - ops < n_ops);
	if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED) {
	    u32 err, bi = op->user_data;
	    if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
		err = e;
	    else
		err = MACSEC_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	    b[bi]->error = node->errors[err];
	    nexts[bi] = MACSEC_DECRYPT_NEXT_DROP;
	    n_fail--;
	}
	op++;
    }
}

static_always_inline void
macsec_process_chained_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vnet_crypto_op_t * ops, vlib_buffer_t * b[],
			 u16 * nexts, vnet_crypto_op_chunk_t * chunks, int e)
{

  vnet_crypto_op_t *op = ops;
  u32 n_fail, n_ops = vec_len (ops);

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_chained_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);
      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 err, bi = op->user_data;
	  if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	    err = e;
	  else
	    err = MACSEC_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	  b[bi]->error = node->errors[err];
	  nexts[bi] = MACSEC_DECRYPT_NEXT_DROP;
	  n_fail--;
	}
      op++;
    }
}

/*
 * Assumes "tail" starts after the beginning of the penultimate buffer
 */
always_inline void
macsec_remove_tail(
    vlib_main_t		*vm,
    vlib_buffer_t	*b,
    vlib_buffer_t	*last,
    u16			tail)
{
    vlib_buffer_t *before_last = b;

    if (last->current_length > tail) {
	last->current_length -= tail;
	return;
    }
    ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);

    while (b->flags & VLIB_BUFFER_NEXT_PRESENT) {
	before_last = b;
	b = vlib_get_buffer (vm, b->next_buffer);
    }
    before_last->current_length -= tail - last->current_length;
    vlib_buffer_free_one (vm, before_last->next_buffer);
    before_last->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
}

/*
 * ICV is split across last two buffers, so move it to the last
 * buffer and return pointer to it
 */
static_always_inline u8 *
macsec_move_icv(
    vlib_main_t			*vm,
    vlib_buffer_t		*first,
    macsec_decrypt_post_data2_t	*pd2,
    u16				icv_sz,
    u16				*dif)
{
    vlib_buffer_t *before_last, *bp;
    u16 last_sz = pd2->lb->current_length;
    u16 first_sz = icv_sz - last_sz;

    bp = before_last = first;
    while (bp->flags & VLIB_BUFFER_NEXT_PRESENT) {
	before_last = bp;
	bp = vlib_get_buffer (vm, bp->next_buffer);
    }

    u8 *lb_curr = vlib_buffer_get_current (pd2->lb);
    memmove (lb_curr + first_sz, lb_curr, last_sz);
    clib_memcpy_fast (lb_curr, vlib_buffer_get_tail (before_last) - first_sz,
		      first_sz);
    before_last->current_length -= first_sz;
    clib_memset (vlib_buffer_get_tail (before_last), 0, first_sz);
    if (dif)
      dif[0] = first_sz;
    pd2->lb = before_last;
    pd2->icv_removed = 1;
    pd2->free_buffer_index = before_last->next_buffer;
    before_last->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
    return lb_curr;
}

/*
 * caller supplies length of payload including icv length
 * returns length of payload not including  icv length
 */
static_always_inline u32
macsec_decrypt_chain_crypto(
    vlib_main_t			*vm,
    macsec_per_thread_data_t	*ptd,
    macsec_decrypt_post_data2_t	*pd2,
    vlib_buffer_t		*b,
    u8				icv_sz,
    u8				*start,
    u32				start_len,	/* includes icv */
    u8				**tag,
    u16				*n_ch)
{
    vnet_crypto_op_chunk_t	*ch;
    vlib_buffer_t		*cb = b;
    u16				n_chunks = 1;
    u32				total_len;

    vec_add2 (ptd->chunks, ch, 1);
    total_len = ch->len = start_len;
    ch->src = ch->dst = start;
    cb = vlib_get_buffer (vm, cb->next_buffer);
    n_chunks = 1;

    while (1) {
	vec_add2 (ptd->chunks, ch, 1);
	n_chunks += 1;
	ch->src = ch->dst = vlib_buffer_get_current (cb);
	if (pd2->lb == cb) {

		/*
		 * Macsec: find icv == "tag"
		 */
		if (pd2->lb->current_length < icv_sz) {
		    u16 dif = 0;
		    *tag = macsec_move_icv (vm, b, pd2, icv_sz, &dif);

		    /* this chunk does not contain crypto data */
		    n_chunks -= 1;
		    /* and fix previous chunk's length as it might have
		       been changed */
		    ASSERT (n_chunks > 0);
		    if (pd2->lb == b) {
			total_len -= dif;
			ch[-1].len -= dif;
		    } else {
			total_len = total_len + pd2->lb->current_length -
			  ch[-1].len;
			ch[-1].len = pd2->lb->current_length;
		    }
		    break;
		} else
		    *tag = vlib_buffer_get_tail (pd2->lb) - icv_sz;

	    if (pd2->icv_removed)
	      total_len += ch->len = cb->current_length;
	    else
	      total_len += ch->len = cb->current_length - icv_sz;
	} else
	    total_len += ch->len = cb->current_length;

	if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	  break;

	cb = vlib_get_buffer (vm, cb->next_buffer);
    }

    if (n_ch)
      *n_ch = n_chunks;

    return total_len;
}

static_always_inline void
macsec_decrypt_prepare_sync_op(
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,
    macsec_per_thread_data_t	*ptd,
    vnet_crypto_op_t		***crypto_ops,
    vnet_crypto_op_t		***integ_ops,
    vnet_crypto_op_t		*op,
    ipsec_sa_t			*sa0,
    u8				*payload,	/* now encrypted data start */
    u16				len,		/* NOT incl iv, icv */
    u8				*aad,		/* new */
    u8				aad_len,	/* new */
    u8				icv_sz,
    u8				*iv,		/* new */
    u8				iv_sz,
    macsec_decrypt_post_data_t	*pd,
    macsec_decrypt_post_data2_t	*pd2,
    vlib_buffer_t		*b,
    u16				*next,
    u32				index)
{
    ASSERT(sa0->crypto_dec_op_id != VNET_CRYPTO_OP_NONE);

    vnet_crypto_op_init (op, sa0->crypto_dec_op_id);
    op->key_index = sa0->crypto_key_index;
    op->iv = iv;

    op->aad = aad;
    op->aad_len = aad_len;

    op->tag = payload + len;
    op->tag_len = 16;

    op->src = op->dst = payload;
    op->len = len;
    op->user_data = index;

    if (pd->is_chain && (pd2->lb != b)) {
	/* buffer is chained */
	op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	op->chunk_index = vec_len (ptd->chunks);
/* TBD check that args are correct */
	macsec_decrypt_chain_crypto (vm, ptd, pd2, b, icv_sz,
				  payload, len + pd->icv_sz,
				  &op->tag, &op->n_chunks);
    }

    vec_add_aligned (*(crypto_ops[0]), op, 1, CLIB_CACHE_LINE_BYTES);
}

/*
 * - assumes ICV immediately follows encrypted data
 * - iv and aad pointers should be valid
 * - buffer's nominal data start should be start of encrypted data
 */
static_always_inline int
macsec_decrypt_prepare_async_frame(
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,

    macsec_per_thread_data_t	*ptd,
    vnet_crypto_async_frame_t	**f,
    ipsec_sa_t			*sa0,
    u8				*payload,	/* start of crypto, no iv */
    u16				len,		/* not incl iv, not incl icv */

    u8				*aad,		/* new */
    u8				aad_len,	/* new */
    u8				icv_sz,
    u8				*iv,		/* new */
    u8				iv_sz,
    macsec_decrypt_post_data_t	*pd,
    macsec_decrypt_post_data2_t	*pd2,
    u32				bi,
    vlib_buffer_t		*b,
    u16				*next,
    u16				async_next)
{
    macsec_decrypt_post_data_t	*async_pd = macsec_decrypt_post_data (b);
    macsec_decrypt_post_data2_t	*async_pd2 = macsec_decrypt_post_data2 (b);
    u8				*tag = payload + len;
    u32				key_index;
    u32				crypto_len;
    u32				integ_len = 0;
    i16				crypto_start_offset;
    i16				integ_start_offset = 0;
    u8				flags = 0;

    /* linked algs */
    key_index = sa0->linked_key_index;

    /*
     * TBD Not sure if these next two are needed for macsec (revisit when
     * async mode is working)
     */
    integ_start_offset = payload - b->data;
    integ_len = len;

    if (pd->is_chain) {
	/* buffer is chained */
	integ_len = pd->current_length;

	/* special case when ICV is splitted and needs to be reassembled
	 * first -> move it to the last buffer. Also take into account
	 * that ESN needs to be added after encrypted data and may or
	 * may not fit in the tail.*/
	if (pd2->lb->current_length < icv_sz) {
	    u16 dif = 0;

	    tag = macsec_move_icv(vm, b, pd2, icv_sz, &dif);
	    if (dif)
		integ_len -= dif;

	    if (pd2->lb == b) {
		/* we now have a single buffer of crypto data, adjust
		 * the length (second buffer contains only ICV) */
		len = b->current_length;	/* TBD not sure this is right */
		goto out;
	    }
	} else
	    tag = vlib_buffer_get_tail (pd2->lb) - icv_sz;

	flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
    }

out:
    /* crypto */
    tag = payload + len;

    crypto_start_offset = payload - b->data;
    crypto_len = len;

    if (pd->is_chain && (pd2->lb != b)) {
	/* buffer is chained */
	flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;

	crypto_len = macsec_decrypt_chain_crypto (vm, ptd, pd2, b, icv_sz,
					       payload,
					       len + pd->icv_sz,
					       &tag, 0);
    }

    *async_pd = *pd;
    *async_pd2 = *pd2;
    next[0] = MACSEC_DECRYPT_NEXT_PENDING;

    /* for AEAD integ_len - crypto_len will be negative, it is ok since it
     * is ignored by the engine. */
    return vnet_crypto_async_add_to_frame(
	vm, f, key_index,
	crypto_len,
	integ_len - crypto_len,
	crypto_start_offset,
	integ_start_offset,
	bi, async_next, iv, tag, aad, flags);
}

static_always_inline void
macsec_decrypt_post_crypto(
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,
    macsec_decrypt_post_data_t	*pd,
    macsec_decrypt_post_data2_t	*pd2,
    vlib_buffer_t		*b,
    u16				*next,
    int				__clib_unused is_async,
    u16				*etype_hostorder)
{
    ipsec_main_t	*im = &ipsec_main;
    ipsec_sa_t		*sa0 = vec_elt_at_index (im->sad, pd->sa_index);
    vlib_buffer_t	*lb = b;
    u16			icv_sz;

    /* default drop */
    next[0] = MACSEC_DECRYPT_NEXT_DROP;

    /*
     * redo the anti-reply check
     * in this frame say we have sequence numbers, s, s+1, s+1, s+1
     * and s and s+1 are in the window. When we did the anti-replay
     * check above we did so against the state of the window (W),
     * after packet s-1. So each of the packets in the sequence will be
     * accepted.
     * This time s will be cheked against Ws-1, s+1 chceked against Ws
     * (i.e. the window state is updated/advnaced)
     * so this time the successive s+! packet will be dropped.
     * This is a consequence of batching the decrypts. If the
     * check-dcrypt-advance process was done for each packet it would
     * be fine. But we batch the decrypts because it's much more efficient
     * to do so in SW and if we offload to HW and the process is async.
     *
     * You're probably thinking, but this means an attacker can send the
     * above sequence and cause VPP to perform decrpyts that will fail,
     * and that's true. But if the attacker can determine s (a valid
     * sequence number in the window) which is non-trivial, it can generate
     * a sequence s, s+1, s+2, s+3, ... s+n and nothing will prevent any
     * implementation, sequential or batching, from decrypting these.
     */
    if (ipsec_sa_macsec_anti_replay_check (sa0, pd->pn)) {
	b->error = node->errors[MACSEC_DECRYPT_ERROR_REPLAY];
	return;
    }

    ipsec_sa_macsec_anti_replay_advance (sa0, pd->pn);

    /*
     * For macsec, we need to:
     *
     * 0. ethernet header data and start-of-buffer mark for post-decrypt
     *    packet should be already set up by pre-decrypt code.
     *
     * 1. Check decrypted etype for match against etfs etype. Discard
     *    if non-matching (no other macsec users at this point).
     *
     * 2. Shorten buffer length to remove ICV at the end if needed (see
     *    pd2->icv_removed)
     *
     * 3. advance buffer start by 2 octets (past decrypted etype) because
     *    the (etfs) next node expects it. Putting buffer start just past
     *    ethernet header matches the usual L2 receiving behavior.
     */

    ethernet_header_t	*eh0 = vlib_buffer_get_current (b);

    u16 etype = clib_net_to_host_u16(*(u16 *) ((u8 *)eh0 + (6+6)));

    if (etype_hostorder)
	*etype_hostorder = etype;

    if (etype != ETHERNET_TYPE_ETFS_EXPERIMENTAL)
	return;

    if (pd->is_chain) {
	lb = pd2->lb;
	icv_sz = pd2->icv_removed ? 0 : pd->icv_sz;
	if (pd2->free_buffer_index) {
	    vlib_buffer_free_one (vm, pd2->free_buffer_index);
	    lb->next_buffer = 0;
	}
    } else {
	icv_sz = pd->icv_sz;
    }

    /* shorten buffer length to "remove" ICV */
    if (icv_sz)
	macsec_remove_tail(vm, b, pd2->lb, icv_sz);

    /*
     * ETFS expects start of buffer at start of ethernet payload
     */
    vlib_buffer_advance(b, sizeof(ethernet_header_t));

    next[0] = MACSEC_DECRYPT_NEXT_ETFS_DECAP;
    vnet_buffer(b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
}

/* when submitting a frame is failed, drop all buffers in the frame */
static_always_inline void
macsec_async_recycle_failed_submit(
    vnet_crypto_async_frame_t	*f,
    vlib_buffer_t		**b,
    u16				*next)
{
    u32 n_drop = f->n_elts;

    while (--n_drop) {
	(b - n_drop)[0]->error = MACSEC_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	(next - n_drop)[0] = MACSEC_DECRYPT_NEXT_DROP;
    }
    vnet_crypto_async_reset_frame (f);
}

always_inline uword
macsec_decrypt_inline(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_frame_t	*from_frame,
    int			is_ip6,
    int			is_tun,
    u16			async_next)
{
    ipsec_main_t		*im = &ipsec_main;
    macsec_main_t		*mm = &macsec_main;
    u32				thread_index = vm->thread_index;
    u16				payload_len;
    macsec_per_thread_data_t	*ptd = vec_elt_at_index(mm->ptd, thread_index);
    u32				*from = vlib_frame_vector_args (from_frame);
    u32				n_left = from_frame->n_vectors;
    vlib_buffer_t		*bufs[VLIB_FRAME_SIZE], **b = bufs;
    u16				nexts[VLIB_FRAME_SIZE], *next = nexts;
    macsec_decrypt_post_data_t	pkt_data[VLIB_FRAME_SIZE], *pd = pkt_data;
    macsec_decrypt_post_data2_t	pkt_data2[VLIB_FRAME_SIZE], *pd2 = pkt_data2;
    macsec_decrypt_post_data_t	cpd = { };
    u32				sa_index0;
    u32				current_sa_index = ~0;
    u32				current_sa_bytes = 0;
    u32				current_sa_pkts = 0;
    ipsec_sa_t			*sa0 = 0;
    vnet_crypto_op_t		_op, *op = &_op;
    vnet_crypto_op_t		**crypto_ops = &ptd->crypto_ops;
    vnet_crypto_op_t		**integ_ops = &ptd->integ_ops;
    vnet_crypto_async_frame_t	*async_frame = 0;
    int				is_async = im->async_mode;
    vnet_crypto_async_op_id_t	last_async_op = ~0;
    u8				*eh0;

    vlib_get_buffers (vm, from, b, n_left);
    if (!is_async) {
	vec_reset_length (ptd->crypto_ops);
	vec_reset_length (ptd->integ_ops);
	vec_reset_length (ptd->chained_crypto_ops);
	vec_reset_length (ptd->chained_integ_ops);
    }
    vec_reset_length (ptd->chunks);
    clib_memset_u16 (nexts, -1, n_left);

    while (n_left > 0) {
	u8	*payload;

	pd->post_handoff = 0;
	pd->sci_present = 0;

	if (n_left > 2) {
	    u8 *p;
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    p = vlib_buffer_get_current (b[1]);
	    CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	    p -= CLIB_CACHE_LINE_BYTES;
	    CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

	u32 n_bufs = vlib_buffer_chain_linearize (vm, b[0]);
	if (n_bufs == 0) {
	    b[0]->error = node->errors[MACSEC_DECRYPT_ERROR_NO_BUFFERS];
	    next[0] = MACSEC_DECRYPT_NEXT_DROP;
	    goto next;
	}

	/*
	 * ethernet node advances buffer past ethernet header so we
	 * have to back up here. Don't change the buffer's notion of
	 * start-of-packet until after potential thread handoff below.
	 */
	eh0 = vlib_buffer_get_current (b[0]) - sizeof(ethernet_header_t);

	/*
	 * Use SCI to look up SA
	 */
	BVT (clib_bihash_kv)	kv;
	u8			*pSecTagTciAn = (u8*)eh0 + 14;
	bool			sci_present;

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
	    clib_memcpy(&kv.key, (u8*)eh0 + 6, 6);      /* sender's addr */
	    * (((u8*)(&kv.key)) + 6) = 0;
	    if (*pSecTagTciAn & MACSEC_TCI_FLAG_ES) {
		if (*pSecTagTciAn & MACSEC_TCI_FLAG_SCB)
		    * (((u8*)(&kv.key)) + 7) = 0;
		else
		    * (((u8*)(&kv.key)) + 7) = 1;
	    } else {
		/* invalid, drop packet */
#if 0
		clib_warning ("Invalid TCI flags 0x%x",
			    *pSecTagTciAn & ~MACSEC_TCI_AN_MASK);
#endif
		vlib_node_increment_counter (vm,
					     macsec_decrypt_node.index,
					     MACSEC_DECRYPT_ERROR_INVFLAG, 1);
		MACSEC_INC_SIMPLE_COUNTER (ver_in_pkts_bad_tag, thread_index,
					   vnet_buffer (b[0])->sw_if_index[VLIB_RX],
					   1);

		b[0]->error = node->errors[MACSEC_DECRYPT_ERROR_INVFLAG];
		next[0] = MACSEC_DECRYPT_NEXT_DROP;
		goto next;
	    }
	}

	pd->kv_key = kv.key;		/* debug */
	pd->sci_present = sci_present;	/* debug */

	if (BV(clib_bihash_search)(&macsec_main.decrypt_sa_table, &kv, &kv)) {
            /* search failed, we have no SA. */
#if 0
            clib_warning ("No SA for SCI %ul", kv.key);
#endif
            vlib_node_increment_counter (vm,
                                         macsec_decrypt_node.index,
                                         MACSEC_DECRYPT_ERROR_NOSA, 1);
	    MACSEC_INC_SIMPLE_COUNTER(ver_in_pkts_no_sa, thread_index,
				      vnet_buffer (b[0])->sw_if_index[VLIB_RX],
				      1);
	    b[0]->error = node->errors[MACSEC_DECRYPT_ERROR_NOSA];
	    next[0] = MACSEC_DECRYPT_NEXT_DROP;
	    goto next;
	}

	ASSERT((kv.value & 0xffffffff) == kv.value);	/* fit u32 */
	sa_index0 = kv.value & 0xffffffff;

	if (sa_index0 != current_sa_index) {
	    if (current_sa_pkts)
	      vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					       current_sa_index,
					       current_sa_pkts,
					       current_sa_bytes);
	    current_sa_bytes = current_sa_pkts = 0;

	    current_sa_index = sa_index0;
	    ASSERT (!pool_is_free_index(im->sad, current_sa_index));
	    sa0 = pool_elt_at_index (im->sad, current_sa_index);
	    cpd.icv_sz = sa0->integ_icv_size;
	    cpd.iv_sz = sa0->crypto_iv_size;
	    cpd.sa_index = current_sa_index;

	    /* submit frame when op_id is different then the old one */
	    if (is_async && last_async_op != sa0->crypto_async_dec_op_id) {
		if (async_frame && async_frame->n_elts) {
		    if (vnet_crypto_async_submit_open_frame (vm, async_frame))
		      macsec_async_recycle_failed_submit (async_frame, b, next);
		}
		async_frame =
		  vnet_crypto_async_get_frame (vm, sa0->crypto_async_dec_op_id);
		last_async_op = sa0->crypto_async_dec_op_id;
	    }
	}

	if (PREDICT_FALSE (~0 == sa0->decrypt_thread_index)) {
	    /* this is the first packet to use this SA, claim the SA
	     * for this thread. this could happen simultaneously on
	     * another thread */
	    clib_atomic_cmp_and_swap (&sa0->decrypt_thread_index, ~0,
				      ipsec_sa_assign_thread (thread_index));
	}

	if (PREDICT_TRUE (thread_index != sa0->decrypt_thread_index)) {
	    next[0] = MACSEC_DECRYPT_NEXT_HANDOFF;
	    goto next;
	}

	pd->post_handoff = 1;

	/* undo ethernet node's advance past ethernet header */
        vlib_buffer_push_uninit(b[0], sizeof(ethernet_header_t));

	/* anti-replay check */
	u32	pn;
	int	check;

	clib_memcpy(&pn, (u8*)eh0 + 16, sizeof(pn));
	pn = clib_net_to_host_u32(pn);
	check = ipsec_sa_macsec_anti_replay_check(sa0, pn);
	if (check == IPSEC_SA_MACSEC_REPLAY_FAIL) {
	    vlib_node_increment_counter (vm,
		macsec_decrypt_node.index,
		MACSEC_DECRYPT_ERROR_REPLAY, 1);
	    MACSEC_INC_SIMPLE_COUNTER(rxsc_in_pkts_late, thread_index,
				      sa_index0, 1);

	    b[0]->error = node->errors[MACSEC_DECRYPT_ERROR_REPLAY];
	    next[0] = MACSEC_DECRYPT_NEXT_DROP;
	    goto next;
	} else if (check == IPSEC_SA_MACSEC_REPLAY_DELAYED) {
	    MACSEC_INC_SIMPLE_COUNTER(rxsc_in_pkts_delayed, thread_index,
				      sa_index0, 1);
	    goto next;
	}

	/*
	 * Build AAD
	 *
	 * Remember that we already shifted start of buffer backward by
	 * size of ethernet header above.
	 *
	 * Now prepend MACSEC_AAD_LENGTH before that.
	 */
	u8 *aad = vlib_buffer_push_uninit(b[0], MACSEC_AAD_LENGTH); /* assert */
	u8 aad_len = MACSEC_AAD_LENGTH;

	if (sci_present) {
	    /* SCI is present in security tag */
	    clib_memcpy_fast(aad, (char *)eh0, MACSEC_AAD_LENGTH);
	} else {
	    clib_memcpy_fast(aad, (char *)eh0, MACSEC_AAD_LENGTH - 8);
	    clib_memcpy_fast(aad + (MACSEC_AAD_LENGTH-8), (u8*)(&kv.key), 8); /* SCI */
	}

	/*
	 * Build IV
	 */
	/* See ieee 802.1ae section 14.5 */
	u8 *iv = vlib_buffer_push_uninit(b[0], 12);	/* assert space */

	clib_memcpy_fast(iv, aad + 20, 8);		/* SCI */
	clib_memcpy(iv + 8, (u8*)eh0 + 16, 4);		/* PN */

	/*
	 * restore start-of-packet to beginning of ethernet header
	 */
	vlib_buffer_advance(b[0], MACSEC_AAD_LENGTH+12);

	/* etype field (2 octets) is considered part of macsec tag */
	u16 payload_offset =
	    sizeof(ethernet_header_t) - 2 +
	    (sci_present? MACSEC_TAG_WITHSCI_LENGTH: MACSEC_TAG_NOSCI_LENGTH);

	payload = vlib_buffer_get_current(b[0]) + payload_offset;
	payload_len = b[0]->current_length - payload_offset - cpd.icv_sz;

	/*
	 * We have AAD and IV in a safe buffer area before
	 * the start of packet.
	 *
	 * Now we overwrite the end of the MACSEC security data with
	 * ethernet dst/src addresses just ahead of the encrypted
	 * data. The first two octets of the encrypted data are the
	 * original etype, so this step sets up the desired post-decryption
	 * ethernet header.
	 */
	u8	*eh0_post_decrypt = payload - (6+6);

	clib_memcpy_fast(eh0_post_decrypt, eh0, (6+6));

	/*
	 * shift start-of-packet marker to post-decrypt location
	 */
	vlib_buffer_advance(b[0], (eh0_post_decrypt - eh0));

	/* store packet data for next round for easier prefetch */
	pd->pn = pn;	/* used in post, already in host byte order */
	pd->is_chain = 0;
	pd->current_data = b[0]->current_data;


	pd->sa_index = cpd.sa_index;
	pd->icv_sz = cpd.icv_sz;/* TBD does this get reset if icv_removed? */
	pd->iv_sz = cpd.iv_sz;


	pd2->lb = b[0];
	pd2->free_buffer_index = 0;
	pd2->icv_removed = 0;

	if (n_bufs > 1) {
	    pd->is_chain = 1;
	    /* find last buffer in the chain */
	    while (pd2->lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	      pd2->lb = vlib_get_buffer (vm, pd2->lb->next_buffer);

	    crypto_ops = &ptd->chained_crypto_ops;
	    integ_ops = &ptd->chained_integ_ops;
	}

	pd->current_length = b[0]->current_length;

/* TBD fixme */
	/* gpz: is this test valid for chained buffers? */
	if (pd->current_length < cpd.icv_sz + cpd.iv_sz) {
	    b[0]->error = node->errors[MACSEC_DECRYPT_ERROR_RUNT];
	    next[0] = MACSEC_DECRYPT_NEXT_DROP;
	    goto next;
	}

	current_sa_pkts += 1;
	current_sa_bytes += vlib_buffer_length_in_chain (vm, b[0]);

	if (is_async) {

	    int ret = macsec_decrypt_prepare_async_frame(
		vm, node, ptd, &async_frame, sa0,
		payload, payload_len,	/* len not incl iv, icv */
		aad, aad_len,
		cpd.icv_sz,
		iv, cpd.iv_sz,
		pd, pd2,
		from[b - bufs], b[0], next, async_next);

	    if (PREDICT_FALSE (ret < 0)) {
		macsec_async_recycle_failed_submit (async_frame, b, next);
		goto next;
	    }
	} else {
	    macsec_decrypt_prepare_sync_op(
		vm, node, ptd, &crypto_ops, &integ_ops,
		op, sa0,
		payload, payload_len,	/* len not incl iv, icv */
		aad, aad_len,
		cpd.icv_sz,
		iv, cpd.iv_sz,
		pd, pd2,
		b[0], next, b - bufs);
	}

	MACSEC_INC_SIMPLE_COUNTER(ver_in_octets_validated, thread_index,
			    vnet_buffer (b[0])->sw_if_index[VLIB_RX],
			    b[0]->current_length);
	MACSEC_INC_SIMPLE_COUNTER(rxsc_in_pkts_ok, thread_index,
			    vnet_buffer (b[0])->sw_if_index[VLIB_RX], 1);

	/* next */
next:
	n_left -= 1;
	next += 1;
	pd += 1;
	pd2 += 1;
	b += 1;
    }

    if (PREDICT_TRUE (~0 != current_sa_index))
      vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				       current_sa_index, current_sa_pkts,
				       current_sa_bytes);

    if (is_async) {
	if (async_frame && async_frame->n_elts) {
	    if (vnet_crypto_async_submit_open_frame (vm, async_frame) < 0)
	      macsec_async_recycle_failed_submit (async_frame, b, next);
	}

	/* no post process in async */
	n_left = from_frame->n_vectors;
	vlib_node_increment_counter (vm, node->node_index,
				     MACSEC_DECRYPT_ERROR_RX_PKTS, n_left);
	vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

	return n_left;
    } else {
	macsec_process_ops (vm, node, ptd->crypto_ops, bufs, nexts,
			 MACSEC_DECRYPT_ERROR_DECRYPTION_FAILED);
	macsec_process_chained_ops (vm, node, ptd->chained_crypto_ops,
	  bufs, nexts, ptd->chunks, MACSEC_DECRYPT_ERROR_DECRYPTION_FAILED);
    }

    /*
     * Post decryption round - adjust packet data start and
     * length and next node
     */

    n_left = from_frame->n_vectors;
    next = nexts;
    pd = pkt_data;
    pd2 = pkt_data2;
    b = bufs;

    while (n_left) {
	if (n_left >= 2) {
	    void *data = b[1]->data + pd[1].current_data;

	    /* buffer metadata */
	    vlib_prefetch_buffer_header (b[1], LOAD);

	    /* esp_footer_t */
	    CLIB_PREFETCH (data + pd[1].current_length - pd[1].icv_sz - 2,
			   CLIB_CACHE_LINE_BYTES, LOAD);

	    /* packet headers */
	    CLIB_PREFETCH (data - CLIB_CACHE_LINE_BYTES,
			   CLIB_CACHE_LINE_BYTES * 2, LOAD);
	}

	if (next[0] >= MACSEC_DECRYPT_N_NEXT) {
	  macsec_decrypt_post_crypto (vm, node, pd, pd2, b[0], next, 0, NULL);
	  MACSEC_INC_SIMPLE_COUNTER(ver_in_octets_decrypted, thread_index,
                                    vnet_buffer (b[0])->sw_if_index[VLIB_RX],
                                    b[0]->current_length);
	}

	/* trace: */
	if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
	    macsec_decrypt_trace_t *tr;
	    tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	    sa0 = pool_elt_at_index (im->sad, pd->sa_index);

	    tr->sci_present = pd->sci_present;
	    tr->kv_key = pd->kv_key;
	    tr->step = MACSEC_TRACE_STEP_PRE;

	    tr->crypto_alg = sa0->crypto_alg;
	    tr->integ_alg = sa0->integ_alg;
	    tr->sa_pn = sa0->seq;

	    tr->pn = pd->pn;
	    tr->next = *next;

	    u8	*pEh;

	    if (pd->post_handoff)
		pEh = b[0]->data + pd->current_data;
	    else
		pEh = vlib_buffer_get_current(b[0]) - sizeof(ethernet_header_t);
	    clib_memcpy_fast(((u8 *)(&tr->eh)), pEh, sizeof(tr->eh));
	}

	/* next */
	n_left -= 1;
	next += 1;
	pd += 1;
	pd2 += 1;
	b += 1;
    }

    n_left = from_frame->n_vectors;
    vlib_node_increment_counter (vm, node->node_index,
				 MACSEC_DECRYPT_ERROR_RX_PKTS, n_left);

    vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

    return n_left;
}

/* Node function */
always_inline uword
macsec_decrypt_post_inline(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_frame_t	*from_frame)
{
    ipsec_main_t *im = &ipsec_main;
    u32 *from = vlib_frame_vector_args (from_frame);
    u32 n_left = from_frame->n_vectors;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
    vlib_get_buffers (vm, from, b, n_left);

    while (n_left > 0) {
	macsec_decrypt_post_data_t	*pd;
	u16				etype_hostorder = 0;

	pd = macsec_decrypt_post_data (b[0]);

	if (n_left > 2) {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[1], LOAD);
	}

	if (!pd->is_chain)
	    macsec_decrypt_post_crypto (vm, node, pd, 0, b[0], next, 1,
		&etype_hostorder);
	else {
	    macsec_decrypt_post_data2_t *pd2;

	    pd2 = macsec_decrypt_post_data2 (b[0]);
	    macsec_decrypt_post_crypto (vm, node, pd, pd2, b[0], next, 1,
		&etype_hostorder);
	}

	/*trace: */
	if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
	    macsec_decrypt_trace_t *tr;
	    tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));

	    ipsec_sa_t *sa0 = pool_elt_at_index (im->sad, pd->sa_index);
	    tr->crypto_alg = sa0->crypto_alg;
	    tr->integ_alg = sa0->integ_alg;

	    tr->step = MACSEC_TRACE_STEP_POST;
	    tr->pn = pd->pn;
	    tr->etype = etype_hostorder;
	    tr->next = next[0];
	    clib_memcpy_fast((u8 *)(&tr->eh), vlib_buffer_get_current(b[0]),
		sizeof(tr->eh));
	}

	n_left--;
	next++;
	b++;
    }

    n_left = from_frame->n_vectors;
    vlib_node_increment_counter (vm, node->node_index,
				 MACSEC_DECRYPT_ERROR_RX_POST_PKTS, n_left);

    vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

    return n_left;
}

VLIB_NODE_FN (macsec_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return macsec_decrypt_inline (vm, node, from_frame, 0, 0,
		     macsec_main.decrypt_async_post_next);
}

VLIB_NODE_FN (macsec_decrypt_post_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return macsec_decrypt_post_inline (vm, node, from_frame);
}


VLIB_NODE_FN (macsec_decrypt_pending_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (macsec_decrypt_pending_node) = {
  .name = "macsec-decrypt-pending",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 0
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (macsec_decrypt_node) = {
  .name = "macsec-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(macsec_decrypt_error_strings),
  .error_strings = macsec_decrypt_error_strings,

  .n_next_nodes = MACSEC_DECRYPT_N_NEXT,
  .next_nodes = {
    [MACSEC_DECRYPT_NEXT_DROP] = "error-drop",
    [MACSEC_DECRYPT_NEXT_ETFS_DECAP] = "etfs-decap-rx-macsec",
    [MACSEC_DECRYPT_NEXT_HANDOFF] = "macsec-decrypt-handoff",
    [MACSEC_DECRYPT_NEXT_PENDING] = "macsec-decrypt-pending",
  },
};

VLIB_REGISTER_NODE (macsec_decrypt_post_node) = {
  .name = "macsec-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_macsec_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(macsec_decrypt_error_strings),
  .error_strings = macsec_decrypt_error_strings,

  .sibling_of = "macsec-decrypt",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

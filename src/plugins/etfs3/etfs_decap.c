/*
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * Copyright (c) 2015 Cisco and/or its affiliates.
 *
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/dpo/dpo.h>	/* INDEX_INVALID */
#include <vnet/macsec/macsec.h>
#include <vnet/macsec/macsec_sa.h>
#include <vppinfra/error.h>

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

#include <vnet/l2/l2_xcrw.h>

#include <etfs3/etfs3.h>
#include <etfs3/etfs_put.h>
#include <etfs3/etfs_format.h>
#include <etfs3/etfs_fragment.h>

#define foreach_etfs_decap_next		\
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ETFS_DECAP_NEXT_##v,
typedef enum {
    foreach_etfs_decap_next
#undef _
    ETFS_DECAP_N_NEXT,
} etfs_decap_next_t;


/*
 * caller should always free buffer after we return
 *
 * Regarding counters: it is possible for a parsing error to
 * occur late in a tunnel frame after a good component has
 * been decoded and queued for transmission. So dropped tunnel
 * frames do not imply that all contained user-frame components
 * have been dropped.
 */
static inline void
_parse_one(
    vlib_main_t			*vm,
#if 0
    vlib_node_runtime_t		*node,
    vlib_frame_t		*frame,
#endif
    state_decap_flow_v2_t	*df,
    vlib_buffer_t		*b0,
    u32				bi0,
    u32				**send,
    u32				**drop)
{
    datablock_reassembly_cursor_t	cursor;
    u32					consumed;
    u32					cursor_offset;
    u32					blic;
#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
    u8					ffc_from_header = 0;
    u16					tf_seq_from_header = 0;
#endif
    u8					ffc_counted = 0;

    blic = vlib_buffer_length_in_chain(vm, b0);

    if (b_cursor_set(vm, b0, &cursor, 0)) {
	/* malformed */

	vec_add1(*drop, bi0);
	ETFS_DEBUG(DECAP_MALFORMED, 3, "decap: malformed 1\n");
	ETFS_DECAP_CCTR_INC(RX, TF_DROP_MALF_SET0, df->config.index, blic);
	return;
    }

    u32 remaining = blic;
    bool got_non_pad = false;
    bool got_explicit_pad = false;

    ETFS_DECAP_CCTR_INC(RX, TF_RX, df->config.index, blic);

    while (remaining >= 2) {

	vlib_buffer_t	*uf;
	u16		following_length;

	cursor_offset = 0;

	if (b_get_u16(vm, &cursor, &following_length)) {
	    /* malformed */
	    ETFS_DEBUG(DECAP_MALFORMED, 1, "decap: malformed CT/FL\n");
	    ETFS_DECAP_CCTR_INC(RX, TF_DROP_MALF_CTFL, df->config.index, blic);
	    return;
	}

	if (!following_length) {
	    /* trailing pad - we're done */
	    if (!got_non_pad && !got_explicit_pad)
		ETFS_DECAP_CCTR_INC(RX, TF_RX_ALL_PAD, df->config.index, blic);
#if ETFS_VERIFY_TRAILING_PAD
	    /*
	     * Slooowly run through the pad data and increment counter if
	     * there are any nonzero bytes. Enabling this will probably
	     * affect performance.
	     */
	    u32 count = 0;
	    u8	value;
	    while (! b_cursor_advance(vm, &cursor, 1)) {
		b_get_u8(&cursor, &value);
		if (value)
		    ++count;
	    }
	    if (count)
		ETFS_DECAP_CCTR_INC(RX, TF_NONZERO_PAD, df->config.index, count);
#endif
	    break;
	}

	u8 component_type = (following_length >> 8) & ETFS_MPPCI_ID_MASK8;
	following_length &= ~ETFS_MPPCI_ID_MASK16;

	if (b_cursor_advance(vm, &cursor, 2)) {
	    /* malformed */
	    ETFS_DECAP_CCTR_INC(RX, TF_DROP_MALF_CTFL_ADV,
		df->config.index, blic);
	    ETFS_DEBUG(DECAP_MALFORMED, 1, "decap: malformed ct/fl advance\n");
	    return;
	}

	if (component_type == ETFS_MPPCI_ID_EXPLICIT_PAD) {
#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
	    /*
	     * First explicit pad has count of full frames in tunnel pkt
	     * (debug only)
	     */
	    if (!got_explicit_pad && (following_length == 4)) {
		datablock_reassembly_cursor_t	c = cursor;
		b_get_u16(vm, &c, &tf_seq_from_header);
		b_cursor_advance(vm, &c, 3);
		b_get_u8(&c, &ffc_from_header);

		if (tf_seq_from_header != df->decoupler.tf_seq_debug) {
		    ETFS_DECAP_SCTR_INC(RX, TF_SEQ_MISMATCH, df->config.index);
		} else {
		    ETFS_DECAP_SCTR_INC(RX, TF_SEQ_OK, df->config.index);
		}
		df->decoupler.tf_seq_debug++;
	    }
#endif
	    got_explicit_pad = true;
	    goto next_component;
	}

	if (component_type == ETFS_MPPCI_ID_FRAME) {

	    got_non_pad = true;

	    /* peel off component and send */
	    u32 uf_ix;
	    ETFS_DECAP_CCTR_INC(RX, C_FULL, df->config.index, following_length);
	    uf = b_clone_partial(vm, &cursor, following_length, NULL, &uf_ix,
#if ETFS_TX_MULTISEG_INDIRECT
		true
#else
		false
#endif
	    );
	    if (uf) {
		vnet_buffer(uf)->sw_if_index[VLIB_TX] = df->config.if_index_tx;
		vec_add1(*send, uf_ix);
#if ETFS_ENABLE_BUFFER_NOTES
		vlib_buffer_note_add(uf, ">%s", __func__);
#endif
		++ffc_counted;
		ETFS_DECAP_CCTR_INC(DECODE, FULL_SENT,
		    df->config.index, following_length);
	    } else {
		ETFS_DECAP_CCTR_INC(DECODE, FULL_DROP_CLONE,
		    df->config.index, following_length);
	    }
	} else if (component_type == ETFS_MPPCI_ID_FRAGMENT) {

	    got_non_pad = true;

	    /* peel off component and send to reassembler */
	    u32	sequence;
	    bool flag_initial = false;
	    bool flag_final = false;
	    bool flag_express = false;

	    ETFS_DECAP_CCTR_INC(RX, C_FRAG, df->config.index, following_length-4);

	    if (b_get_u32(vm, &cursor, &sequence)) {
		/* malformed */
		ETFS_DECAP_CCTR_INC(RX, TF_DROP_MALF_FRAG_GETSEQ,
		    df->config.index, following_length-4);
		ETFS_DEBUG(DECAP_MALFORMED, 1, "decap: malformed fragment (1)\n");
		return;

	    }
	    if (sequence & (ETFS_MPPCI_FRAG_INITIAL << 24))
		flag_initial = true;
	    if (sequence & (ETFS_MPPCI_FRAG_FINAL << 24))
		flag_final = true;
	    if (sequence & (ETFS_MPPCI_FRAG_EXPRESS << 24))
		flag_express = true;
	    sequence &= 0x00ffffff;	/* 24-bit sequence */

	    /*
	     * move past fragment flags/number
	     */
	    if (b_cursor_advance(vm, &cursor, 4)) {
		/* malformed */
		ETFS_DECAP_CCTR_INC(RX, TF_DROP_MALF_FRAG_GETSEQ_ADV,
		    df->config.index, following_length-4);
		ETFS_DEBUG(DECAP_MALFORMED, 1,
		    "decap: mal frag 2: remaining %u, FL %u,  seq %u, IF %u, LF %u\n",
		    remaining, following_length, sequence, flag_initial, flag_final);
		return;
	    }

	    cursor_offset += 4;

	    u32 uf_ix;

	    /* allow_indirect because we will copy in reassembly */
	    uf = b_clone_partial(vm, &cursor, following_length-4, NULL, &uf_ix, true);
	    if (uf) {
		ETFS_DECAP_CCTR_INC(DECODE, FRAG_QUEUED,
		    df->config.index, following_length-4);
		etfs_receive_fragment(vm, df, uf_ix, flag_initial, flag_final,
		    flag_express, sequence, send, drop);
	    } else {
		ETFS_DECAP_CCTR_INC(DECODE, FRAG_DROP_CLONE,
		    df->config.index, following_length-4);
	    }
	} else {

	    got_non_pad = true;

	    /* count unknown component type */
	    ETFS_DECAP_CCTR_INC(RX, C_UNKNOWN,
		    df->config.index, following_length-4);
	}

next_component:
	consumed = 2 + following_length;

	if (consumed > remaining) {
	    /* malformed */
	    ETFS_DECAP_CCTR_INC(RX, TF_DROP_FRAMING,
		df->config.index, following_length-4);
	    ETFS_DEBUG(DECAP_MALFORMED, 1, "decap: malformed 4a\n");
	    return;
	}

	u32	new_remaining = remaining - consumed;

	/* if we processed last component, return */
	if (new_remaining == 0)
	    break;

	if (b_cursor_advance(vm, &cursor, following_length - cursor_offset)) {
	    /* malformed */
	    ETFS_DECAP_CCTR_INC(RX, TF_DROP_FRAMING_ADV,
		df->config.index, following_length-4);
	    ETFS_DEBUG(DECAP_MALFORMED, 1, "decap: malformed 4b\n");
	    return;
	}
	remaining = new_remaining;
    }
    if (got_non_pad) {
	ETFS_DECAP_CCTR_INC(RX, TF_RX_UF, df->config.index, blic);
	ETFS_DECAP_SCTR_ADD(RX, FFC_COUNTED_TOTAL, df->config.index,
	    ffc_counted);
#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
	if (ffc_from_header != ffc_counted) {
	    ETFS_DECAP_SCTR_INC(RX, FFC_MISMATCH, df->config.index);
	} else {
	    ETFS_DECAP_SCTR_INC(RX, FFC_OK, df->config.index);
	}
#endif
    } else if (got_explicit_pad)
	ETFS_DECAP_CCTR_INC(RX, TF_RX_EPAD_ONLY, df->config.index, blic);
    else
	/* unexpected */
	ETFS_DECAP_CCTR_INC(RX, TF_RX_UNKNOWN, df->config.index, blic);
}

/* trace mppdus */
/*
 * For decap receive trace, buffer trace flags should be set by
 * interface rx node, so we only test buffers to see if they have
 * the trace flag set.
 */
static inline void
etfs_decap_rx_trace_buffers(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    u32			next_index,
    u32			*bi,
    u32			n,
    bool		new)
{
    for (uint i = 0; i < n; i++) {
	vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	if (new)
	    vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 1);
	if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		etfs_trace_mppdu(vm, node, b0, 0, false);
    }
}

/* trace user frames */
static inline void
etfs_decap_tx_trace_buffers(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    u32			next_index,
    u32			*bi,
    u32			n,
    bool		new)
{
    /* TBD we are originating here: so is using this trace count right? */
    uword n_trace = vlib_get_trace_count (vm, node);

    ETFS_DEBUG(DECAP_TX_TRACE, 5, "n_trace: %lu\n", n_trace);

    if (PREDICT_FALSE (n_trace)) {
	n = clib_min (n_trace, n);

	for (uint i = 0; i < n; i++) {
	    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	    if (new)
		vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 1);
	    etfs_trace_updu(vm, node, b0, true);
	}
	vlib_set_trace_count (vm, node, n_trace - n);
    }
}


typedef struct
{
    u8	is_macsec;
} decap_rx_runtime_data_t;


static uword
decap_rx_node_fn (
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_frame_t	*frame)
{
    u32			n_left_from;
    u32			*from;

    u32			drop_buffers[VLIB_FRAME_SIZE];
    u32			*drop = drop_buffers;
    uword		npkts = 0;


    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    if (!n_left_from)
	return 0;

    BVT(clib_bihash)	*pDecapFlowTable;

    pDecapFlowTable =
	((decap_rx_runtime_data_t *)(node->runtime_data))->is_macsec ?
	    &etfs3_main.decap_flow_table_macsec:
	    &etfs3_main.decap_flow_table;

    ETFS_DEBUG(DECAP, 1, "decap: rx %u, is_macsec: %u\n",
	n_left_from,
	((decap_rx_runtime_data_t *)(node->runtime_data))->is_macsec);

    ETFS_GLOBAL_SCTR_ADD(DECAP_RX, n_left_from);

    state_decap_flow_v2_t	*last_df = NULL;
    u32				last_sw_if_index0 = ~0u;

    bool			full = false;

    while (n_left_from > 0) {
	/*
	 * First implementation handles 1 packet at a time
         */
	u32			bi0;
	vlib_buffer_t		*b0;
        u32			sw_if_index0;
	BVT (clib_bihash_kv)	kv;
	state_decap_flow_v2_t	*df;


	bi0 = from[0];
	from += 1;
	n_left_from -= 1;
	++npkts;

	b0 = vlib_get_buffer (vm, bi0);

	/*
	 * Discard all-trailing-pads before flow lookup
	 *
	 * TBD should also look for explicit pads whose following length
	 * occupies the entire packet
	 */
	u8	*p = vlib_buffer_get_current(b0);

	if (!*p && !*(p+1)) {
	    /*
	     * all trailing-pad
	     */
	    *drop++ = bi0;
	    ETFS_GLOBAL_SCTR_INC(DECAP_RX_ALLPAD);
	    continue;
	}

	/* buffer has field indicating which interface index it arrived on */
        sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	if (last_df && (last_sw_if_index0 == sw_if_index0)) {
	    df = last_df;
	    if (full) {
                *drop++ = bi0;
		ETFS_DECAP_SCTR_INC(RX, DROP_DDQ_FULL, df->config.index);
		continue;
	    }
	} else {

	    full = false;

	    /*
	     * Look up decap flow & state based on received interface.
	     * See vnet/l2/l2_fib.h'l2fib_valid_swif_seq_num for example.
	     */
	    kv.key = sw_if_index0;
	    if (BV (clib_bihash_search)(pDecapFlowTable, &kv, &kv)) {
		/* no per-interface config: discard packet */
                *drop++ = bi0;
#if ETFS_ENABLE_BUFFER_NOTES
		vlib_buffer_note_add(b0, "!%s", __func__);
#endif
		ETFS_DEBUG(DECAP_NOFLOW, 1,
		    "decap: interface index %u: no match\n",
		    sw_if_index0);
		ETFS_GLOBAL_SCTR_INC(DECAP_DROP_NOFLOW);
		continue;
	    }
	    df = (state_decap_flow_v2_t *)(kv.value);
	    last_df = df;
	    last_sw_if_index0 = sw_if_index0;
	}

#if ETFS_DDQ_USE_VEC
	/*
	 * old implementation, not safe if decoupler is on a different thread
	 */
	if (vec_len(df->decoupler.rx) > (1 << ETFS_DDQ_LOG2)) {
	    full = true;
            *drop++ = bi0;
	    ETFS_DECAP_SCTR_INC(RX, DROP_DDQ_FULL, df->config.index);
	    continue;
	}
	vec_add1(df->decoupler.rx, bi0);
#else
	/*
	 * new implementation, sring with single producer, single consumer
	 */
	u32 q_open = SRING_OPEN(&df->decoupler.q);

	if (!q_open) {
	    full = true;
            *drop++ = bi0;
	    ETFS_DECAP_SCTR_INC(RX, DROP_DDQ_FULL, df->config.index);
	    continue;
	}

	u32 actual = SRING_PUT(&df->decoupler.q, &bi0, 1);
	if (!actual) {
	    /* shouldn't happen */
            *drop++ = bi0;
	    ETFS_DECAP_SCTR_INC(RX, DROP_SRING_PUT_FAIL, df->config.index);
	    continue;
	}
#endif
#if ETFS_ENABLE_BUFFER_NOTES
	vlib_buffer_note_add(b0, ">%s", __func__);
#endif
    }

    if (drop != drop_buffers)
	b_free_bi_chain(vm, drop_buffers, drop - drop_buffers, __func__);

    return npkts;
}

decap_rx_runtime_data_t decap_rx_runtime_data_non_macsec = {
    .is_macsec = 0,
};

decap_rx_runtime_data_t decap_rx_runtime_data_macsec = {
    .is_macsec = 1,
};

VLIB_REGISTER_NODE (etfs3_decap_rx_node) = {
  .function = decap_rx_node_fn,
  .name = "etfs-decap-rx",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_etfs_mppdu_trace,
  .runtime_data = &decap_rx_runtime_data_non_macsec,
  .runtime_data_bytes = sizeof(decap_rx_runtime_data_non_macsec),
  .vector_size = sizeof (u32),
/*  .format_trace = format_sample_trace, */
  .type = VLIB_NODE_TYPE_INTERNAL,
#if 0
  .n_errors = ETFS3_N_DECAP_ERROR,
  .error_strings = etfs3_decap_error_strings,
#endif
  .n_next_nodes = ETFS_DECAP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
#define _(s,n) [ETFS_DECAP_NEXT_##s] = n,
    foreach_etfs_decap_next
#undef _
  },
};

VLIB_REGISTER_NODE (etfs3_decap_rx_node_macsec) = {
  .function = decap_rx_node_fn,
  .name = "etfs-decap-rx-macsec",
  .runtime_data = &decap_rx_runtime_data_macsec,
  .runtime_data_bytes = sizeof(decap_rx_runtime_data_macsec),
  .vector_size = sizeof (u32),
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_etfs_mppdu_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
#if 0
  .n_errors = ETFS3_N_DECAP_ERROR,
  .error_strings = etfs3_decap_error_strings,
#endif
  .n_next_nodes = ETFS_DECAP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
#define _(s,n) [ETFS_DECAP_NEXT_##s] = n,
    foreach_etfs_decap_next
#undef _
  },
};

typedef struct {
    u32			AllowedPkts;	/* max packets to process */
    vlib_node_runtime_t	*node_runtime;
    vlib_main_t		*vm;
    u32			thread_index;
} decap_flow_arg_t;

/*
 * For one flow, process up to N tunnel packets that have been queued
 * by the receiver. The caller specifies N.
 *
 * The purpose of this arrangement is to yield back to the scheduler
 * to avoid starving the network interface receiver of cycles.
 * (When the receive code called the decap processing code directly,
 * it was observed to be called with 4000+ packets at a time under
 * load, apparently resulting in rx-miss events on the network interface.
 */
static inline u32
decap_processor_flow(
    state_decap_flow_v2_t	*df,
    void			*arg)
{
    decap_flow_arg_t	*a = (decap_flow_arg_t *)arg;
    vlib_main_t		*vm = a->vm;
    vlib_node_runtime_t	*node = a->node_runtime;
    uint		remaining;
    uint		count;
    u32			*pBi;
    u32			bi[VLIB_FRAME_SIZE];
    u32			*send = df->decoupler.send;
    u32			*drop = df->decoupler.drop;
    u32			*to = NULL;
    u32			*eto = NULL;
    u32			next_index;
    uword		npkts = 0;

    ASSERT(vec_len(send) == 0);
    ASSERT(vec_len(drop) == 0);

#if ETFS_DDQ_USE_VEC
    /*
     * old - vector
     */
    remaining = vec_len(df->decoupler.rx);
    ETFS_DEBUG(DECAP_RX_TRACE, 5, "allowed: %u, pkts: %u\n",
	a->AllowedPkts, remaining);
    if (!remaining)
	return 0;

    remaining = count = clib_min(remaining, a->AllowedPkts);

    /* There is only one next node: interface-output */
    next_index = ETFS_DECAP_NEXT_INTERFACE_OUTPUT;

    for (pBi = df->decoupler.rx; remaining; ++pBi, --remaining) {
	vlib_buffer_t		*b0;

	b0 = vlib_get_buffer (vm, *pBi);
	_parse_one(a->vm, df, b0, *pBi, &send, &drop);
	etfs_decap_rx_trace_buffers(vm, node, next_index, pBi,
	    1, false);
	vec_add1(drop, *pBi);
    }
    vec_shift(df->decoupler.rx, count);

#else

    /* 
     * new - sring
     */
    ASSERT(a->AllowedPkts <= VLIB_FRAME_SIZE);
    remaining = count = SRING_GET(&df->decoupler.q, bi, a->AllowedPkts);
    if (!remaining)
	return 0;

    /* There is only one next node: interface-output */
    next_index = ETFS_DECAP_NEXT_INTERFACE_OUTPUT;

    for (pBi = bi; remaining; ++pBi, --remaining) {
	vlib_buffer_t		*b0;

	b0 = vlib_get_buffer (vm, *pBi);
	_parse_one(a->vm, df, b0, *pBi, &send, &drop);
	etfs_decap_rx_trace_buffers(vm, node, next_index, pBi,
	    1, false);
	vec_add1(drop, *pBi);
    }
#endif

#if ETFS_ENABLE_BUFFER_NOTES
    /* debug */
    for (uint i = 0; i < vec_len(send); ++i) {
	vlib_buffer_t *b;
	b = vlib_get_buffer(vm, send[i]);
	vlib_buffer_note_add(b, ")%s", __func__);
    }
#endif

    u32 holes = 0;
    for (uint i = 0; i < vec_len(send); ++i) {
	vlib_buffer_t *b = vlib_get_buffer(vm, send[i]);
	u64 blen = vlib_buffer_length_in_chain(vm, b);

#if ETFS_TX_MULTISEG_INDIRECT
	if (B_CHAIN_COMPACT(vm, !(df->config.tx_port_is_dpdk), &send[i],
	    df->config.tx_mtu)) {
	    ETFS_DECAP_SCTR_INC(TX, COMPACT_FAILED, df->config.index);
	    ETFS_DECAP_CCTR_INC(DECODE, DROP_NOBUFS, df->config.index, blen);

	    /*
	     * Compact/flatten failed (probably buffer starvation).
	     * Drop the packet because the downstream node(s) might not
	     * be equipped to handle indirect buffers and might leak them.
	     */
	    ++holes;
	    vec_add1(drop, send[i]);
	    send[i] = ~0u;
	} else {
	    ETFS_DECAP_CCTR_INC(DECODE, PKT_SENT_TOTAL, df->config.index, blen);
	}
#else
	ASSERT(!(b->flags & VLIB_BUFFER_NEXT_PRESENT));
	ETFS_DECAP_CCTR_INC(DECODE, PKT_SENT_TOTAL, df->config.index, blen);
#endif
    }

    remaining = vec_len(send);

    ETFS_DEBUG(DECAP_RX_TRACE, 5, "send vec_len: %u\n", remaining);

    while (remaining) {
	/*
	 * NB if there are no holes (usual case), we process the
	 * "send" buffer list in big chunks so hit this conditional
	 * relatively few times.
	 */
	if (holes) {
	    /*
	     * slow path: some of the slots in the "send" vector are NULL
	     * probably due to buffer starvation. In that case it's OK
	     * if we are a bit less efficient.
	     *
	     * Note that "remaining" includes the empty slots.
	     */
	    if (send[npkts] != (typeof(send[npkts]))~0u) {
		/* have packet */
		count = 1;
	    } else {
		npkts += 1;
		remaining -= 1;
		continue;
	    }
	} else {
	    count = remaining;
	}
	/* on 1st iter, to==NULL and this sets to and eto */
	vlib_put_get_next_frame (vm, node, next_index, to, eto, ~0);
	count = clib_min(count, eto - to);
	clib_memcpy_fast(to, send+npkts, count * sizeof (*to));
#if ETFS_ENABLE_BUFFER_NOTES
	for (u32 *bi = to; bi < to + count; ++bi) {
	    vlib_buffer_t *b;
	    b = vlib_get_buffer(vm, *bi);
	    vlib_buffer_note_add(b, ">%s", __func__);
	}
#endif
	etfs_decap_tx_trace_buffers(vm, node, next_index, to, count, true);
	to += count;
	npkts += count;
	remaining -= count;
#if 0	/* replaced with +npkts above and vec_free() below */
 	vec_shift(send, count);
#endif
    }

    /* put final frame */
    vlib_put_next_frame_with_cnt (vm, node, next_index, to, eto, ~0);

    /* reset the temp array and save it incase it changed */
    vec_reset_length(send);
    df->decoupler.send = send;

    if (drop) {
	b_free_bi_chain(vm, drop, vec_len(drop), __func__);
        /* reset the temp array and save it incase it changed */
        vec_reset_length(drop);
        df->decoupler.drop = drop;
    }

    return npkts - holes;
}


VLIB_NODE_FN(etfs_decap_processor_node)
(vlib_main_t *vm, vlib_node_runtime_t *node_runtime, vlib_frame_t * __clib_unused frame)
{
    uword		npkts = 0;
    decap_flow_arg_t	a;

    a.node_runtime = node_runtime;
    a.vm = vm;
    a.thread_index = vlib_get_thread_index ();

    etfs_thread_main_t		*tm;
    struct state_decap_flow_v2	**df;

    tm = vec_elt_at_index(etfs3_main.workers_main, vlib_get_thread_index());

    u32	nflows = vec_len(tm->flows_decap[ETFS_DECAP_POLLER_PROCESSOR]);
    a.AllowedPkts = (ETFS_DECAP_MAX_PROCESS_PER_ITER / nflows) + 1;
    a.AllowedPkts = clib_min(a.AllowedPkts, VLIB_FRAME_SIZE);

    vec_foreach(df, tm->flows_decap[ETFS_DECAP_POLLER_PROCESSOR]) {
	npkts += decap_processor_flow(*df, &a);
    }

    return npkts;
}

VLIB_REGISTER_NODE(etfs_decap_processor_node) = {
    .name = "etfs-decap-processor",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_DISABLED,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .format_trace = format_etfs_mppdu_trace,

    .n_next_nodes = ETFS_DECAP_N_NEXT,
    .next_nodes = {
#define _(s,n) [ETFS_DECAP_NEXT_##s] = n,
    foreach_etfs_decap_next
#undef _
    },
};


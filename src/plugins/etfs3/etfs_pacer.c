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

/*
 * Much of this code is based on iptfs (thanks Chris!)
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

#include <plugins/etfs3/etfs3.h>
#include <plugins/etfs3/etfs_format.h>
#include <plugins/etfs3/etfs_encap.h>

static inline void
etfs_pacer_trace_buffers(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    u32			*bi,
    u32			n,
    u16			generation)
{
    uword	n_trace = vlib_get_trace_count (vm, node);

    if (PREDICT_FALSE (n_trace)) {
	n_trace = clib_min (n_trace, n);
	for (uint i = 0; i < n_trace; i++) {
	    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	    etfs_trace_mppdu(vm, node, b0, generation, true);
	}
	vlib_set_trace_count (vm, node, n_trace - 1);
    }
}

#define PACK_SLOTS_PACKETS(slots, pkts) (((u64) (slots) << 32) | (u64) (pkts))
#define UNPACK_SLOTS_PACKETS(rv, s, p)   \
  do                                     \
    {                                    \
      (s) = (((rv) >> 32) & 0xFFFFFFFF); \
      (p) = ((rv)&0xFFFFFFFF);           \
    }                                    \
  while (0)

/* un-inline */
static bool
_finish_inprogress(
    vlib_main_t			*vm,		/* IN */
    struct state_encap_flow_v2	*ef,		/* IN */
    u32				*pBi,		/* OUT */
    u32				*uf_bytes,	/* OUT */
    u32				*nbufs)		/* OUT */
{
    bool got_one;

    got_one = encap_finish_inprogress(vm, ef, pBi, uf_bytes, nbufs);

    if (got_one) {
	/* count as part of encoder output */
	ETFS_ENCAP_CCTR_INC(RX, ENCODE_TF_PLUCKED, ef->config.index, *uf_bytes);
    } else {
	/* preclude garbage to caller */ 
	*uf_bytes = 0;
	*nbufs = 0;
    }

    return got_one;
}

static inline u64
encap_pacer_queue_packets(
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,
    u32				thread_index,
    state_encap_flow_v2_t	*ef,
    u16				missed)
{
    u32				n_avail;
    vlib_buffer_t		*inpb = NULL;
    uint			count;
    u32				bi[VLIB_FRAME_SIZE + 1];
    u32				sizes[VLIB_FRAME_SIZE + 1];
    u32				inprogress_payload = 0;

    n_avail = iptfs_bufq_n_enq (&ef->encap.pacer_queue);

    if (n_avail)
	ETFS_ENCAP_SCTR_INC(PACER, POLL_DUE_HAVE_TF, ef->config.index);
    else
	ETFS_ENCAP_SCTR_INC(PACER, POLL_DUE_NO_TF, ef->config.index);

    if (ef->encap.bi_inprogress != ~0u) {
	inpb = vlib_get_buffer (vm, ef->encap.bi_inprogress);
	vlib_prefetch_buffer_header (inpb, STORE);
    }

    u32 q_open = SRING_OPEN (&ef->output.q);
    if (!q_open) {
	ETFS_ENCAP_SCTR_INC(PACER, POLL_DUE_SRING_NO_OPEN, ef->config.index);
	return 0;
    }

    u32 n_req = clib_min(q_open, n_avail);
#if ETFS_PACER_MAX_BURST > 0
    n_req = clib_min (n_req, missed + 1 + ETFS_PACER_MAX_BURST);
#endif

    n_req = clib_min (n_req, VLIB_FRAME_SIZE - 1);

    count = iptfs_bufq_ndequeue (&ef->encap.pacer_queue, bi, sizes, n_req);

    if (!count && !inpb)
	return 0;

    if (!count) {
	/*
	 * Only inprogress
	 * We must have an in-progress (see conditional above that returns)
	 */
	ASSERT (inpb);
#if ETFS_PACER_MAX_BURST < 1
	/*
	 * NOTE:A: If we haven't missed any slots yet, delay 1 slot prior to
	 * sending the partial in-progress to give it a chance to fill. On the
	 * output side a full pad will be sent so this is not noticeable on the
	 * tunnel.
	 */
	if (missed == 0)
	  return 0;
#endif

	/*
	 * in-progress has some data
	 * (in-progress handled below)
	 */

    } else if (count < q_open) {

	/*
	 * We have full packets to queue, a free slot in the queue,
	 * and maybe an in-progress too
	 */
	if (count < missed) {
	    /*
	     * We have N slots, we have 2 (or more) time slots left to send
	     * after sending the full packets, so send the in-progress. This
	     * is similar to only delaying 1 time slots from NOTE:A: above.
	     * If we didn't send here we'd be delaying at least 2.
	     * (in-progress handled below)
	     */
	} else if (count > missed) {
	    /* Send all full packets, no need to send in-progress */
	    inpb = NULL;
	} else {
	    /*
	     * We have full packets and exactly one extra slot available.
	     * Send the in-progress if we have it, since we have a flow of
	     * packets going and otherwise we might add extra pad now
	     * (due to output adding a full pad while we were coming
	     * back around).
	     *
	     * This is the same code as the first conditional :)
	     * (in-progress handled below)
	     */
	}
    }
    if (inpb && (count < q_open)) {
	u32	bi_inprogress;
	u32	nsegs;
	bool	want_compact;
	if (_finish_inprogress(vm, ef, &bi_inprogress,
	    &inprogress_payload, &nsegs)) {

#if ! ETFS_TX_MULTISEG_INDIRECT
	    /*
	     * Transition to all-direct/single-seg buffers.
	     * Should not see multi-seg in encap path now.
	     */
	    ASSERT(nsegs == 1);
#endif

	    want_compact = (nsegs > ETFS_TX_MAX_SEGS) ||
		ef->config.send_direct_bufs_only;

	    (void)want_compact;
	    if (B_CHAIN_COMPACT(vm, want_compact, &bi_inprogress,
		ef->config.tx_mtu)) {

		/*
		 * Buffer starvation or some other weird case
		 */

		ETFS_ENCAP_CCTR_INC(PACER, TF_DROP_COMPACT,
		    ef->config.index, inprogress_payload);
		b_free_bi_chain(vm, &bi_inprogress, 1, __func__);

		/*
		 * disabuse code below of the notion we sent an
		 * inprogress packet
		 */
		inprogress_payload = 0;

	    } else {

		sizes[count] = inprogress_payload;
		bi[count++] = bi_inprogress;
	    }
	}
    }

    /*
     * Decrease pacer queue payload count by amount dequeued
     *
     * NB encoder includes user-frame data written to in-progress buffer
     * in the pacer queue depth. 
     */
    u32		total_payload = 0;
    for (uint i = 0; i < count; i++)
	total_payload += sizes[i];
    ASSERT (ef->encap.pacer_queue_depth.size >= total_payload);
    ef->encap.pacer_queue_depth.size -= total_payload;

    if (inprogress_payload) {
	ETFS_ENCAP_CCTR_INC(PACER, TF_PLUCKED, ef->config.index,
	    inprogress_payload);
	if (count > 1) {
	    ETFS_ENCAP_CCTR_ADD(PACER, TF_DEQUEUED, ef->config.index,
		count-1, (total_payload - inprogress_payload));
	}
    } else {
	ETFS_ENCAP_CCTR_ADD(PACER, TF_DEQUEUED, ef->config.index,
	    count, total_payload);
    }

    /*
     * Recheck transmit queue available slot count because our
     * count may have increased due to an in-progress buffer.
     */
    u32	new_q_open = SRING_OPEN (&ef->output.q);
    if (new_q_open < q_open) {
	/*
	 * This should never happen
	 */
	ETFS_ENCAP_CCTR_INC(PACER, QSLOTS_SHRANK,
	    ef->config.index, q_open - new_q_open);
    }
    q_open = new_q_open;
    if (q_open < count) {
	/*
	 * gpz: I don't think this can happen now as it would imply
	 * q_open got smaller
	 */
	ETFS_DEBUG_F(PACER, 0, "open tx q slots below need %u<%u, "
	    "is output thread running on a different clock?",
	    q_open, count);
	/* free excess buffers */
	b_free_bi_chain(vm, &bi[q_open], count - q_open, __func__);

	for (uint i = q_open; i < count; ++i) {
	    ETFS_ENCAP_CCTR_INC(PACER, TF_DROP_QSLOTS,
		ef->config.index, sizes[i]);
	    total_payload -= sizes[i];
	}

	count = q_open;
    }

    ef->pacer.pacer_gen++;
    etfs_pacer_trace_buffers(vm, node, bi, count, ef->pacer.pacer_gen);

    u32 actual = SRING_PUT (&ef->output.q, bi, count);

    ETFS_DEBUG_F(PACER, 3, "enqueued: %u to etfs-output", actual);

    if (actual < count) {
	/* shouldn't happen */

	ETFS_ENCAP_SCTR_INC(PACER, SRING_PUT_FAILURE, ef->config.index);
	for (uint i = actual; i < count; ++i) {
	    ETFS_ENCAP_CCTR_INC(PACER, SRING_PUT_FAIL,
		ef->config.index, sizes[i]);
	    total_payload -= sizes[i];
	}
	/* free excess buffers */
	b_free_bi_chain(vm, &bi[actual], count - actual, __func__);
    }

    ETFS_ENCAP_CCTR_ADD(PACER, TF_ENQUEUED, ef->config.index,
	actual, total_payload);

    return actual;
}

typedef struct {
    uword		*pNpkts;	/* caller's sent-packet counter */
    vlib_node_runtime_t	*node_runtime;
    vlib_main_t		*vm;
    u32			thread_index;
} encap_flow_arg_t;

/*
 * For one flow, move one or more packets from the pacer queue to the
 * transmit queue; grab an in-progress packet if necessary and available.
 */
static inline u32
encap_pacer_flow(
    state_encap_flow_v2_t	*ef,
    void			*arg)
{
    encap_flow_arg_t		*a = (encap_flow_arg_t *)arg;
    u64				now = clib_cpu_time_now ();
    u64				due;	/* cpu time when next tx pkt is due */
    i64				delta;
    i64				count = 1;
    uword			npkts = 0;

    if (PREDICT_FALSE(!ef->pacer.next_desired_tx_cputicks))
	ef->pacer.next_desired_tx_cputicks = now;

    due = ef->pacer.next_desired_tx_cputicks;
    delta = now - due;

    if (delta < 0) {
	/* too early */
	return 0;
    }

    /*
     * if the actual time since we were last here is greater than the
     * desired transmission interval, compute how many intervals have
     * elapsed.
     */
    if (delta > (i64)ef->config.tx_interval_cputicks) {
	count = (i64) ((delta / ef->config.tx_interval_cputicks) + 1);
	/*
	 * Limit to one frame's worth of packets
	 */
	if (count > 1)
	    ETFS_ENCAP_SCTR_INC(PACER, POLL_MISSED, ef->config.index);
	if (count > VLIB_FRAME_SIZE) {
	    ETFS_ENCAP_SCTR_INC(PACER, POLL_LIMITED_FRAME_SIZE,
		ef->config.index);
	}
	count = clib_min(count, VLIB_FRAME_SIZE);
	due = now;
    }

    /*
     * Store the time when we should send the next packet
     */
    ef->pacer.next_desired_tx_cputicks = due + ef->config.tx_interval_cputicks;

    npkts = encap_pacer_queue_packets(a->vm, a->node_runtime,
	a->thread_index, ef, count);

    return npkts;
}

VLIB_NODE_FN(etfs_encap_pacer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node_runtime, vlib_frame_t * __clib_unused frame)
{
    uword		npkts = 0;
    encap_flow_arg_t	a;

    a.pNpkts = &npkts;
    a.node_runtime = node_runtime;
    a.vm = vm;
    a.thread_index = vlib_get_thread_index ();

    etfs_thread_main_t		*tm;
    struct state_encap_flow_v2	**ef;

    tm = vec_elt_at_index(etfs3_main.workers_main, vlib_get_thread_index());

    vec_foreach(ef, tm->flows[ETFS_ENCAP_POLLER_PACER]) {
	npkts += encap_pacer_flow(*ef, &a);
    }

    return npkts;
}

VLIB_REGISTER_NODE(etfs_encap_pacer_node) = {
    .name = "etfs-encap-pacer",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_DISABLED,
    .format_trace = format_etfs_mppdu_trace,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};


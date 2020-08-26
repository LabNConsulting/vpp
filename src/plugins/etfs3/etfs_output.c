/*
 * May 24 2019, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2019-2020, LabN Consulting, L.L.C.
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
#include <vppinfra/error.h>
#include <vppinfra/ring.h>
#include <vppinfra/time.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

#include <plugins/etfs3/etfs3.h>
#include <plugins/etfs3/etfs_format.h>
#include <plugins/etfs3/etfs_put.h>

#define foreach_etfs_output_next			\
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ETFS_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_etfs_output_next
#undef _
    ETFS_OUTPUT_N_NEXT,
} etfs_output_next_t;

#define foreach_etfs_output_error                                         \
  _ (TX_NO_PADS, "ETFS-output-err all pad packets skipped due to config") \
  _ (TX_CATCHUP_DROPS, "ETFS-output-err time slots dropped to catch up")

typedef enum
{
#define _(sym, str) ETFS_OUTPUT_ERROR_##sym,
  foreach_etfs_output_error
#undef _
      ETFS_OUTPUT_N_ERROR,
} etfs_output_error_t;

static char *etfs_output_error_strings[] = {
#define _(sym, string) string,
    foreach_etfs_output_error
#undef _
};

/*
 * Output byte counter queue
 *
 * A circular buffer containing datapoints from the past. Each datapoint
 * comprises a timestamp and a byte count. Using these datapoints it is
 * possible to compute average traffic rates over the range of times
 * represented in the buffer.
 */

void
etfs_output_byte_counter_q_init(state_encap_flow_v2_t *ef)
{
    clib_ring_new(ef->output.output_byte_counter_q, ETFS_N_OUTPUT_BYTE_CTR);
}

void
etfs_output_byte_counter_q_free(state_encap_flow_v2_t *ef)
{
    vec_free(ef->output.output_byte_counter_q);
}

static inline void
etfs_output_byte_counter_q_append(
    state_encap_flow_v2_t *ef,
    u64 packets,
    u64 bytes,
    u64 dues,
    u64 cputicks)
{
    etfs_tc_t	datum;
    etfs_tc_t	*slot;

    datum.fsecs = unix_time_now();
    datum.packets = packets;
    datum.bytes = bytes;
    datum.dues = dues;
    datum.cputicks = cputicks;

    slot = clib_ring_enq(ef->output.output_byte_counter_q);
    if (PREDICT_TRUE(!slot)) {
	clib_ring_deq(ef->output.output_byte_counter_q);
	slot = clib_ring_enq(ef->output.output_byte_counter_q);
	ASSERT(slot);
    }
    *slot = datum;
}

/* nth ranges from 1 to queue size */
static inline void *
clib_ring_get_nth(void *v, u32 elt_bytes, u32 n)
{
    clib_ring_header_t *h = clib_ring_header (v);
    u32 slot;
    u32	vl = _vec_len (v);

    ASSERT(n);
    ASSERT(n <= vl);

    if (h->n_enq < n)
	return 0;

    /* get oldest slot (n == 1) */
    if (h->n_enq > h->next)
	slot = vl + h->next - h->n_enq;
    else
	slot = h->next - h->n_enq;

    slot += (n - 1);
    if (slot >= vl)
	slot -= vl;

    return (void *) ((u8 *) v + elt_bytes * slot);
}

#define clib_ring_get_nth(ring, n) \
    clib_ring_get_nth(ring, sizeof(ring[0]), n)

u8 *
etfs_output_byte_counter_q_format(u8 *s, va_list *args)
{
    state_encap_flow_v2_t	*ef;
    u32				n_enq;
#if ETFS_AGO_USE_UNIX_TIME
    f64				now = unix_time_now();
#endif
    u64				cputicks_now = clib_cpu_time_now();

    ef = va_arg (*args, state_encap_flow_v2_t *);

    u32 indent = format_get_indent(s);

    s = format(s, "Tunnel transmit rates:\n");

    n_enq = clib_ring_n_enq(ef->output.output_byte_counter_q);
    while (n_enq) {
	etfs_tc_t	*slot;
	f64		ago;
	f64		prate;
	f64		brate;
	f64		dues_rate;
	f64		cputick_rate;


	slot = clib_ring_get_nth(ef->output.output_byte_counter_q, n_enq);
#if ETFS_AGO_USE_UNIX_TIME
	ago = now - slot->fsecs;
#else
	ago = ((f64)(cputicks_now - slot->cputicks)) / 
	    ((f64)((vlib_get_main())->clib_time.clocks_per_second));
#endif
	prate = (ef->output.c_out_pkts - slot->packets)/ago;
	brate = 8 * (ef->output.c_out_bytes - slot->bytes)/ago;

	dues_rate = (ef->output.c_out_dues - slot->dues)/ago;
	cputick_rate = (cputicks_now - slot->cputicks)/ago;

	s = format(s, "%Usince %5.1fs ago: %5.1e pkts/s, %5.1e bits/s, %5.1e dues/s, %5.1e ct/s\n",
	    format_white_space, indent,
	    ago, prate, brate, dues_rate, cputick_rate);

	--n_enq;
    }

    return s;
}

static inline void
etfs_output_trace_buffers(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    u32			next_index,
    u32			*bi,
    u32			n,
    u32			generation,
    bool		new)
{
    uword n_trace = vlib_get_trace_count (vm, node);

    ETFS_DEBUG(OUTPUT_TRACE, 5, "n_trace: %lu\n", n_trace);

    if (PREDICT_FALSE (n_trace)) {

	n = clib_min (n_trace, n);

	for (uint i = 0; i < n; i++) {
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	  if (new)
	    vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 1);
	  etfs_trace_mppdu(vm, node, b0, generation, true);
	}
	vlib_set_trace_count (vm, node, n_trace - n);
    }
}

typedef struct
{
  u32 sa_index, slots, avail, user, sent;
} etfs_output_event_send_data_t;

always_inline u32
etfs_output_get_zpool_buffers(
    vlib_main_t			*vm,
    struct state_encap_flow_v2 *ef,
    u32				*buffers,
    u32				n_alloc)
{
  etfs_zpool_t *zpool = ef->output.zpool;

  ASSERT (n_alloc > 0);

  /* This function only works if one thread is the consumer */
  u32 count = etfs_zpool_get_buffers (zpool, buffers, n_alloc, true,
				       &ef->output.zpool_track);
  if (PREDICT_FALSE (count < n_alloc))
    {
#if 0 /* TBD fixme for single-thread  operation */
      /* This is only the case when we are running on main only */
      if (PREDICT_FALSE (!satd->tfs_zpool_running &&
			 !satd->tfs_pad_req_pending))
	goto ping;
#endif
      return count;
    }
#if 0 /* TBD fixme for single-thread  operation */
  else if (PREDICT_FALSE (!ef->output.zpool_running &&
			  !satd->tfs_pad_req_pending))
    {
      /* This is only the case when we are running on main only */
      if (PREDICT_FALSE (etfs_zpool_get_avail (zpool) <= zpool->trigger))
	{
	ping:
	  satd->tfs_pad_req_pending = true;
	  vlib_process_signal_event_mt (vm, etfs_zpool_process_node.index,
					IPTFS_EVENT_TYPE_MORE_BUFFERS,
					sa_index);
	}
    }
#endif
  return count;
}

static inline uword
etfs_output_packets_inline(
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,
    u32				thread_index,
    struct state_encap_flow_v2	*ef,
    u16				n)
{
    u32					next_index;
    u32					bi[VLIB_FRAME_SIZE];
    uword				npkts = 0;
    uint				count;
    u32					*to = NULL;
    u32					*eto = NULL;
#if ETFS_ENABLE_ELOG
    etfs_output_event_send_data_t	*esd = NULL;
#endif

#if 0 /* TBD stats */
  iptfs_prefetch_pcounter (IPTFS_PCNT_OUTPUT_RX, thread_index, sa_index);
  iptfs_prefetch_pcounter (IPTFS_PCNT_OUTPUT_TX, thread_index, sa_index);
#endif

    ASSERT (n <= VLIB_FRAME_SIZE);


    ef->output.output_gen++;

#if ETFS_ENABLE_ELOG
    /* Log an event with our data for this run */
    ELOG_TYPE_DECLARE (event_send) = {
      .format = "etfs-output send-data time slots %d user-avail "
		"(approx) %d user-sent %d sent %d",
      .format_args = "i4i4i4i4",
    };
    esd = ETFS_ELOG (event_send, ef->output.output_track);
    esd->slots = n;
    esd->user = 0;
    esd->avail = SRING_NELT (&ef->output.q);
#endif

    /*
     * We used to just store a next_node_index in the per-flow
     * configuration at flow setup time, But the macsec backend
     * can be changed during operation, which changes the specific
     * node to use for encrypting outbound etfs packets. So we track
     * that node in the etfs global structure (etfs3_main) and retrieve
     * it each time here.
     */
    if (ef->config.macsec_enabled)
	next_index = etfs3_main.macsec_encrypt_next_node_index;
    else
	next_index = ETFS_OUTPUT_NEXT_INTERFACE_OUTPUT;

    /* the number available could actually go up here */
    count = SRING_GET (&ef->output.q, bi, n);
    if (count) {
	ETFS_ENCAP_SCTR_INC(OUT, POLL_DUE_HAVE_TF, ef->config.index);

	vlib_put_get_next_frame (vm, node, next_index, to, eto, ~0);
	/* We are assuming we will have enough space */
	ASSERT (count <= eto - to);
	clib_memcpy_fast (to, bi, count * sizeof (*to));
	to += count;
	npkts += count;

#if ETFS_ENABLE_ELOG
	if (esd)
	    esd->user += count;
#endif

	u64 bytes = count * ef->config.framesize;

	ETFS_ENCAP_CCTR_ADD(OUT, TF_SENT_UF, ef->config.index,
	    count, bytes);
	ETFS_ENCAP_CCTR_ADD(OUT, TF_SENT_TOTAL, ef->config.index,
	    count, bytes);
	ef->output.c_out_pkts += count;
	ef->output.c_out_bytes += bytes;

	etfs_output_trace_buffers (vm, node, next_index, bi, count,
				  ef->output.output_gen, true);

	ETFS_DEBUG_F(ENCAP_OUTPUT, 3, "sending %u of %u full",
			 count, n);


	/* See if we are done (i.e., if we've sent count) */
	if (count >= n) {
	    ASSERT (count == n);
	    goto done;
	}
	n -= count;
    } else {
	ETFS_ENCAP_SCTR_INC(OUT, POLL_DUE_NO_TF, ef->config.index);
    }

    /*
     * Get and send pad packets
     */

    if (PREDICT_FALSE (ef->config.encap_no_pad_only)) {
	/* Pretend like we send all the pads */
	vlib_node_increment_counter (vm, etfs_output_node.index,
				   ETFS_OUTPUT_ERROR_TX_NO_PADS, n);
	ETFS_ENCAP_CCTR_ADD(OUT, TF_SENT_ALLPAD_FAKE, ef->config.index,
	    n, n * ef->config.framesize);

    } else {
	count = etfs_output_get_zpool_buffers (vm, ef, bi, n);

	if (count < n) {
	    ETFS_DEBUG_F (ENCAP_OUTPUT, 3,
		"got fewer zbufs than requested: %u < %u",
		count, n);
	    ETFS_ENCAP_CCTR_ADD(OUT, TF_UNDERRUN_ALLPAD, ef->config.index,
		(n - count), (n - count) * ef->config.framesize);

	}

	vlib_put_get_next_frame (vm, node, next_index, to, eto, ~0);
	/* We are assuming we will have enough space! */
	ASSERT (count <= eto - to);
	clib_memcpy_fast (to, bi, count * sizeof (*to));
	to += count;
	npkts += count;

	ETFS_DEBUG_F (ENCAP_OUTPUT, 3, "sending %u of %u all-pad",
			 count, n);

	u64 bytes = count * ef->config.framesize;

	ETFS_ENCAP_CCTR_ADD(OUT, TF_SENT_ALLPAD, ef->config.index,
	    count, bytes);
	ETFS_ENCAP_CCTR_ADD(OUT, TF_SENT_TOTAL, ef->config.index,
	    count, bytes);
	ef->output.c_out_pkts += count;
	ef->output.c_out_bytes += bytes;

	/* User is not normally going to want all-pad traced */
	if (ef->config.all_pad_trace) {
	    etfs_output_trace_buffers (vm, node, next_index, bi, count,
				      ef->output.output_gen, true);
	}
    }

done:
  vlib_put_next_frame_with_cnt (vm, node, next_index, to, eto, ~0);

#if ETFS_ENABLE_ELOG
  if (esd)
    esd->sent = npkts;
#endif

  return npkts;
}

extern vlib_node_registration_t etfs_output_node;

static inline uword
etfs_output_poll_inline(
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,
    u32				thread_index,
    state_encap_flow_v2_t	*ef)
{
    u64				now = clib_cpu_time_now ();
    u64				due;
    i64				delta;
    i64				count = 1;

    /* Make sure this hasn't happened */
#if 0
    ASSERT (!pool_is_free_index (ipsec_main.sad, sa_index));
#endif
    ASSERT (ef->thread.node_running[ETFS_ENCAP_POLLER_OUTPUT]);

    due = ef->output.next_desired_tx_cputicks;
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
	if (count > VLIB_FRAME_SIZE) {
	    ETFS_ENCAP_SCTR_ADD(OUT, TF_HELD_FSLIMIT, ef->config.index,
		count - VLIB_FRAME_SIZE);
	    count = VLIB_FRAME_SIZE;
	}
	due = now;
	ETFS_ENCAP_SCTR_INC(OUT, TF_SLIPS, ef->config.index);
    }

    /*
     * Store the time when we should send the next packet
     */
    ef->output.next_desired_tx_cputicks = due + ef->config.tx_interval_cputicks;

    /*
     * send the packets
     */

    ETFS_ENCAP_SCTR_ADD(OUT, TF_DUE, ef->config.index, count);
    ef->output.c_out_dues += count;

    u32 sent = etfs_output_packets_inline(vm, node, thread_index, ef, count);

    if (sent < count)
	ETFS_ENCAP_SCTR_ADD(OUT, TF_NOTSENT, ef->config.index, (count-sent));

    /*
     * Update output byte counter ring as needed (once every few seconds or so)
     */
    if (now > ef->output.next_desired_tx_output_byte_counter_cputicks) {
	etfs_output_byte_counter_q_append(ef,
	    ef->output.c_out_pkts, ef->output.c_out_bytes,
	    ef->output.c_out_dues, now);

	ef->output.next_desired_tx_output_byte_counter_cputicks =
	    now + ef->config.output_byte_counter_interval_cputicks;
    }

    return sent;
}

/* *INDENT-OFF* */
VLIB_NODE_FN (etfs_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t * __clib_unused frame)
{
    uword	npkts = 0;
    u32		thread_index = vlib_get_thread_index();

    etfs_thread_main_t		*tm;
    state_encap_flow_v2_t	**ppEf;

    tm = vec_elt_at_index(etfs3_main.workers_main, thread_index);

    vec_foreach(ppEf, tm->flows[ETFS_ENCAP_POLLER_OUTPUT]) {
	npkts += etfs_output_poll_inline(vm, node, thread_index, *ppEf);
    }

    return npkts;
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (etfs_output_node) = {
    .name = "etfs-output",
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    // Need to add length to va_args for this function to use.
    // .format_buffer = format_iptfs_header,
    .format_trace = format_etfs_mppdu_trace,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_DISABLED,

    .n_errors = ARRAY_LEN (etfs_output_error_strings),
    .error_strings = etfs_output_error_strings,

    .n_next_nodes = ETFS_OUTPUT_N_NEXT,
    .next_nodes = {
#define _(s,n) [ETFS_OUTPUT_NEXT_##s] = n,
    foreach_etfs_output_next
#undef _
    },
};

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

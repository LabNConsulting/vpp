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

#include <etfs3/etfs3.h>
#include <etfs3/etfs_encap.h>


static inline vlib_buffer_t *
encap_init_inprogress(
    vlib_main_t			*vm,
    struct state_encap_flow_v2	*ef)
{
    u32			nbufs;
    vlib_buffer_t	*b_inprogress;

    /*
     * Set up new empty in-progress buffer
     */

#if ETFS_ENCAP_ALLOC_FROM_HEAP
    /* this is the slower method because we have to zero trailing pad bytes */
    nbufs = b_alloc_bi(vm, &ef->encap.bi_inprogress, __func__);
#else
    /*
     * These buffers have the ethernet header pre-written
     */
    nbufs = etfs_zpool_get_buffers(ef->encap.zpool, &ef->encap.bi_inprogress,
	1, false, &ef->encap.zpool_track);
#endif

    /*
     * NB buffer starvation is kind of a bug deal
     */
    if (!nbufs)
	return NULL;

    b_inprogress = vlib_get_buffer(vm, ef->encap.bi_inprogress);
    ef->encap.space_avail = clib_min(ef->config.framesize,
	vlib_buffer_space_left_at_end(vm, b_inprogress));
    ef->encap.ffc_inprogress = 0;
    ef->encap.nsegs_inprogress = 1;

#if ETFS_ENCAP_ALLOC_FROM_HEAP
    ef->encap.space_avail = clib_min(ef->config.framesize,
	vlib_buffer_space_left_at_end(vm, b_inprogress) - sizeof(ef->config.ether_header));

    /*
     * write ethernet header
     */
    char	*p;
    u16		len = sizeof(ef->config.ether_header);

    p = vlib_buffer_put_uninit(b_inprogress, len);
    clib_memcpy_fast(p, &ef->config.ether_header, len);
    /* space_avail does not include outer ethernet header */
    /* ef->encap.space_avail -= len; */
#endif

#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
    {
	u8	*p, *q, *endq;
	u16	sequence = clib_host_to_net_u16(ef->encap.tf_seq_debug++);

	/*
	 * 16-bit seq in first two bytes, ffc in 4th byte
	 */
	q = (u8 *)&sequence;
	endq = q+2;
	p = vlib_buffer_put_uninit(b_inprogress, 6);
	*p++ = ETFS_MPPCI_ID_EXPLICIT_PAD | 0;
	*p++ = 4;

	while (q < endq)
	    *p++ = *q++;

	*p++ = 0;
	*p++ = 0;

	ef->encap.space_avail -= 6;
	ef->encap.ffc_inprogress = 0;
    }
#endif

    /*
     * Set transmit interface
     */
    vnet_buffer(b_inprogress)->sw_if_index[VLIB_TX] = ef->config.if_index_tx;

    if (ef->config.macsec_enabled)
        vnet_buffer(b_inprogress)->ipsec.sad_index = ef->config.ipsec_sa_index;

    ETFS_DEBUG(ENCAP_INPROGRESS, 1, "returning b_inprogress %p\n",
	b_inprogress);

    return b_inprogress;
}

static inline vlib_buffer_t *
encap_enqueue_inprogress_init_new(
    vlib_main_t			*vm,
    struct state_encap_flow_v2	*ef)
{
    u32			bi_inprogress;
    u32			uf_bytes;
    u32			nsegs;

    if (!encap_finish_inprogress(vm, ef, &bi_inprogress, &uf_bytes, &nsegs))
	return NULL;

    /* TBD need a way to track number of segments in in-progress buffer */

    /*
     * If required, normalize buffer by copying data into a single
     * direct buffer.
     *
     * Conditions that might trigger this normalization:
     *
     * 1. too many segments - some drivers (e.g., mvpp2) throw away
     *    packet chains longer than some limit. See ETFS_TX_MAX_SEGS.
     *
     * 2. etfs is built to always emit direct buffers (indirect
     *    buffers are a special feature of dpdk and are not recognized
     *    by vpp). See ETFS3_TRANSMIT_MULTISEG.
     *
     * 3. transmit device driver is known to be non-dpdk (determined
     *    when the flow is provisioned).
     */
    bool	want_compact;

#if ! ETFS_TX_MULTISEG_INDIRECT
    /*
     * transition to all-direct/single-seg buffers
     * Should not see multi-seg in encap path
     */
    ASSERT(nsegs == 1);
#endif

    want_compact = (nsegs > ETFS_TX_MAX_SEGS) || ef->config.send_direct_bufs_only;

    (void)want_compact; /* fix warning/error */
    if (B_CHAIN_COMPACT(vm, want_compact,
	&bi_inprogress, ef->config.tx_mtu)) {

	ETFS_ENCAP_CCTR_INC(RX, ENCODE_TF_DROP_COMPACT, ef->config.index, uf_bytes);
	ETFS_DEBUG(ENCAP_INPROGRESS, 1, "B_CHAIN_COMPACT failed, dropping\n");
	b_free_bi_chain(vm, &bi_inprogress, 1, "f-comfl");
    } else {

	/*
	 * enqueue in-progress buffer to pacer queue
	 */
	if (iptfs_bufq_enqueue(&ef->encap.pacer_queue, bi_inprogress, uf_bytes))
	    ETFS_ENCAP_CCTR_INC(RX, ENCODE_TF_ENQUEUED, ef->config.index,
		uf_bytes);
	else
	    ETFS_ENCAP_CCTR_INC(RX, ENCODE_TF_DROP_QSLOTS, ef->config.index,
		uf_bytes);
    }

    /*
     * Set up new empty in-progress buffer
     */
    return encap_init_inprogress(vm, ef);
}

#define has_room_for_user_frame(ef, length_uf)	\
    ((ef)->encap.space_avail >= (2 + (length_uf)))

#define has_room_for_fragment(ef)		\
    ((ef)->encap.space_avail >= (6 + (ef)->config.min_fragment))

/*
 * NB caller frees user frame
 */
static void
encap_encode(
    vlib_main_t			*vm,
    struct state_encap_flow_v2	*ef,
    u32				bi_uf)
{
    vlib_buffer_t			*b_uf;
    u64					length_uf;
    u64					length_uf_saved;
    u64					length_uf_orig;
    vlib_buffer_t			*b_inprogress = NULL;
    u8					*dst = NULL;

    datablock_reassembly_cursor_t	scurs;
    bool				initial_fragment;
    u32					newqsz;
    u16					fragment_length = 0;

    /* TBD for performance we could get buffer ptr and length from caller */
    b_uf = vlib_get_buffer(vm, bi_uf);
    length_uf_orig = length_uf = vlib_buffer_length_in_chain(vm, b_uf);

    ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_RX, ef->config.index, length_uf);

    /* only 14 bits to encode length */
    ASSERT(length_uf < 0x3fff);

    /* TBD flow config should calculate proper depth values */
    /*
     * the queue depth we track includes not only contents of the
     * pacer_queue but also the in-progress buffer
     */
    newqsz = iptfs_bufq_check_limit(&ef->encap.pacer_queue,
	&ef->encap.pacer_queue_depth, length_uf);

    if (!newqsz) {
	/* discard user frame  - nothing to do since caller frees */
	ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_DROP_QFULL, ef->config.index, length_uf);
	return;
    }

    /*
     * Get fresh in-progress buffer if needed. There are two cases:
     *
     * 1. no in-progress buffer. This is not only an initial condition,
     *    but also occurs when the pacer plucks the in-progress buffer.
     *
     * 2. If there is no room to add either the full frame or a fragment.
     *    We check here at the start even though the fragmentation loop
     *    handles an out-of-space condition by allocating buffers as needed,
     *    because allocating a new buffer could make it possible to encode
     *    the current full frame without fragmenting.
     */
    if (ef->encap.bi_inprogress == ~0u) {

	b_inprogress = encap_init_inprogress(vm, ef);
	if (!b_inprogress) {
	    /*
	     * Buffer starvation. drop incoming user packet (caller frees)
	     */
	    ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_DROP_NOBUFS,
		ef->config.index, length_uf);
	    return;
	}

    } else if (!has_room_for_user_frame(ef, length_uf) &&
	!has_room_for_fragment(ef)) {

	b_inprogress = encap_enqueue_inprogress_init_new(vm, ef);
	if (!b_inprogress) {
	    /*
	     * Buffer starvation. drop incoming user packet (caller frees)
	     */
	    ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_DROP_NOBUFS,
		ef->config.index, length_uf);
	    return;
	}

    } else
	b_inprogress = vlib_get_buffer(vm, ef->encap.bi_inprogress);

    ETFS_DEBUG(ENCAP_INPROGRESS, 1,
	"bi_inprogress %u, b_inprogress %p\n",
	ef->encap.bi_inprogress, b_inprogress);

    ETFS_DEBUG(ENCAP_SPLIT, 1, "space_avail %u, length_uf %u\n",
	ef->encap.space_avail, length_uf);

    if (has_room_for_user_frame(ef, length_uf)) {
	/*
	 * We have room to store the entire user frame
	 */
	u64	len_copied;

#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
	/*
	 * first payload in this tunnel frame, count for debug
	 */
	if (!ETFS_INPROG_HAS_PAYLOAD(b_inprogress, ef))
	    ETFS_ENCAP_SCTR_INC(RX, ENCODE_TF_SEQ, ef->config.index);
#endif


	/*
	 * write 2-octet header
	 */

	dst = vlib_buffer_put_uninit(b_inprogress, 2);
	*dst = (length_uf >> 8) & 0x3f;
	*(dst+1) = length_uf & 0xff;
	dst += 2;

	/*
	 * Assumes buffer large enough to hold entire packet
	 * Copies to in-progress buffer
	 */
	len_copied = vlib_buffer_contents(vm, bi_uf, dst);
	ASSERT(len_copied == length_uf);
	vlib_buffer_put_uninit(b_inprogress, len_copied);

	ef->encap.space_avail -= (2 + len_copied);
	ef->encap.uf_bytes += len_copied;

#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
	ef->encap.ffc_inprogress += 1;
#endif

	/*
	 * XXX we don't need to do anything about failures to
	 * allocate new inprogress buffer here.
	 */
	if (!has_room_for_fragment(ef))
	    encap_enqueue_inprogress_init_new(vm, ef);

	ef->encap.pacer_queue_depth.size = newqsz;

	ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_ENQUEUED_FULL, ef->config.index, length_uf);

	return;
    }

    /*
     * Try to fragment
     * Fragment header is 6 octets
     */

    /*
     * set source cursor to start of incoming user frame
     */
    b_cursor_set(vm, b_uf, &scurs, 0);
    initial_fragment = true;

#if 0 /* handled below */
    /*
     * we need to make sure there is always enough room for a minimum
     * sized fragment
     */
    ASSERT(ef->encap.space_avail >= (6 + ef->config.min_fragment));
#endif

    length_uf_saved = 0;

    while (length_uf) {

	if (!has_room_for_fragment(ef)) {
	    b_inprogress = encap_enqueue_inprogress_init_new(vm, ef);
	    if (!b_inprogress) {
		/*
		 * buffer allocation failure
		 *
		 * Walk back pacer queue depth by number of
		 * un-encoded bytes, i.e., (length_uf - length_uf_saved)
		 *
		 * TBD current approach will result in tailles fragment
		 * chains at the receiver. Should instead try to avoid
		 * enqueueing fragments until we know we can get all the
		 * buffers.
		 */
		u32 dropped;

		ASSERT(length_uf_orig > length_uf_saved);
		dropped = length_uf_orig - length_uf_saved;
		ASSERT(newqsz >= dropped);
		newqsz -= dropped;

		/*
		 * There are several ways to count these bytes.
		 * We may have already sent some fragments for the
		 * user packet
		 *
		 * 1. Count the bytes not encoded to a tunnel frame
		 *    (i.e., only the dropped bytes)
		 *
		 * OR
		 *
		 * 2. Count all of the user frame bytes, because the
		 *    receiver will not be able to reassemble the
		 *    user frame.
		 */
		ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_TRUNCATE_NOBUFS,
		    ef->config.index, dropped);

		break;
	    }
	}

#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
	/*
	 * first payload in this tunnel frame, count for debug
	 */
	if (!ETFS_INPROG_HAS_PAYLOAD(b_inprogress, ef))
	    ETFS_ENCAP_SCTR_INC(RX, ENCODE_TF_SEQ, ef->config.index);
#endif

	/*
	 * No support for express frames in the encap path yet,
	 * so we always use the default fragment sequence number.
	 *
	 * Note that the fragment length calculation below does not
	 * directly involve the user frame length. That's because
	 * the user frame + 2 octets is bigger than the available space
	 * (see above) and now we need to fit user frame + 6 octets,
	 * which is even bigger.
	 */
	fragment_length = clib_min(length_uf, ef->encap.space_avail - 6);

	u16 following_length = (fragment_length + 4) & 0x3fff;

	ASSERT(following_length == fragment_length + 4);

	ETFS_DEBUG(ENCAP_SPLIT, 1,
	    "length_uf %u, fragment_length %u, following_length %u, IF %u\n",
	    length_uf, fragment_length, following_length, initial_fragment);

	/*
	 * Write first two octets of fragment header
	 */
	dst = vlib_buffer_put_uninit(b_inprogress, 6);

	*dst++ = (following_length >> 8) | ETFS_MPPCI_ID_FRAGMENT;
	*dst++ = following_length & 0xff;

	/* TBD catch bug */
	ASSERT(following_length > 4);

	/*
	 * Third octet is flags
	 */
	if (initial_fragment) {
	    *dst = ETFS_MPPCI_FRAG_INITIAL;
	    initial_fragment = false;
	} else if (fragment_length == length_uf) {
	    *dst = ETFS_MPPCI_FRAG_FINAL;
	} else {
	    *dst = 0;
	}
	ETFS_DEBUG(ENCAP_FRAG, 5, "seq: %u, IF: %u, FF: %u\n",
		ef->encap.frag_seq_default,
		(*dst & ETFS_MPPCI_FRAG_INITIAL)? 1: 0,
		(*dst & ETFS_MPPCI_FRAG_FINAL)? 1: 0);
	dst++;

	/*
	 * 4,5,6 are fragment sequence number
	 */
	*dst++ = (ef->encap.frag_seq_default >> 16) & 0xff;
	*dst++ = (ef->encap.frag_seq_default >>  8) & 0xff;
	*dst   = (ef->encap.frag_seq_default >>  0) & 0xff;

	/*
	 * Copy fragment_length octets from the user frame to the
	 * in-progress buffer.
	 */
	u16 count;

	count = b_copy_append(vm, &scurs, b_inprogress, fragment_length, false,
	    __func__);
	ASSERT(count == fragment_length);

	ef->encap.uf_bytes += count;
	ef->encap.space_avail -= (count + 6);
	length_uf -= count;
	length_uf_saved += count;

	/*
	 * update in-progress segment count
	 */
	if (b_inprogress->flags & VLIB_BUFFER_NEXT_PRESENT) {
	    uint		i = 1;
	    vlib_buffer_t 	*b = b_inprogress;

	    while ((b = vlib_get_next_buffer(vm, b)))
		++i;
	    ef->encap.nsegs_inprogress = i;
	}

	/*
	 * increment fragment sequence number
	 */
	ef->encap.frag_seq_default += 1;
	ef->encap.frag_seq_default &= 0xffffff;	/* 24 bits */

	ETFS_ENCAP_CCTR_INC(RX, ENCODE_FRAG_ENQUEUED,
	    ef->config.index, fragment_length);
    }

    ef->encap.pacer_queue_depth.size = newqsz;

    /*
     * if we can't do anything more with this tunnel frame, enqueue it now.
     *
     * XXX we don't need to do anything about failures to
     * allocate new inprogress buffer here.
     *
     */
    if (!has_room_for_fragment(ef))
	encap_enqueue_inprogress_init_new(vm, ef);

    ETFS_ENCAP_CCTR_INC(RX, ENCODE_PKT_ENQUEUED_FRAGMENTED, ef->config.index,
	length_uf_saved);
}

typedef struct
{
    u8 src[6];
    u8 dst[6];
    u32 sw_if_index;
    u32 buffer_length;
} etfs_encap_rx_trace_t;

static u8 *
format_encap_rx_trace(u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    etfs_encap_rx_trace_t *t = va_arg (*args, etfs_encap_rx_trace_t *);

    s = format (s, "encap_rx: sw_if_index %d dst %U src %U totlen %u",
	t->sw_if_index,
	format_ethernet_address, t->dst,
	format_ethernet_address, t->src,
	t->buffer_length);
    return s;
}


static uword
encap_rx_node_fn (
    vlib_main_t		*vm,
    vlib_node_runtime_t	* node,
    vlib_frame_t	*frame)
{
    u32			n_left_from;
    u32			*from;
    u32			free_buffers[VLIB_FRAME_SIZE];
    u32			*free = free_buffers;
    int			do_trace = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	do_trace = 1;

    ETFS_DEBUG(ENCAP_RX, 1, "n_left_from: %u\n", n_left_from);

    while (n_left_from > 0) {
	u32		bi0;
	vlib_buffer_t	*b0 = NULL;
	u32		sw_if_index0;

	bi0 = from[0];
	from += 1;
	n_left_from -= 1;

	/* buffer has field indicating which interface index it arrived on */
	b0 = vlib_get_buffer(vm, bi0);
	sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	if (do_trace) {
	    ethernet_header_t *h0 = vlib_buffer_get_current (b0);
	    etfs_encap_rx_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	    t->sw_if_index = sw_if_index0;
	    t->buffer_length = vlib_buffer_length_in_chain(vm, b0);
	    clib_memcpy_fast (t->src, h0->src_address, 6);
	    clib_memcpy_fast (t->dst, h0->dst_address, 6);
	}

	/*
	 * Look up encap state for the flow based on received interface.
	 * See vnet/l2/l2_fib.h'l2fib_valid_swif_seq_num for example.
	 */
	BVT (clib_bihash_kv) kv;
	kv.key = sw_if_index0;
	if (BV (clib_bihash_search)(&etfs3_main.encap_flow_table, &kv, &kv)) {
	    /* no per-interface config: discard packet */
            *free++ = bi0;
	    continue;
	}
	state_encap_flow_v2_t *ef = (state_encap_flow_v2_t *)(kv.value);

	/*
	 * Make sure we are running on the thread that the pacer
	 * has been assigned to. TBD assess effect of this line on
	 * performance.
	 */
	ASSERT(ef->encap.rx_thread_index == vlib_get_thread_index());

	encap_encode(vm, ef, bi0);

	/* we must always free */
        *free++ = bi0;
    }

    if (free != free_buffers)
	b_free_bi_chain(vm, free_buffers, free - free_buffers, __func__);

    return frame->n_vectors;
}

VLIB_REGISTER_NODE (etfs_encap_rx_node) = {
  .function = encap_rx_node_fn,
  .name = "etfs-encap-rx",
  .vector_size = sizeof (u32),
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_encap_rx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
#if 0
  .n_errors = ETFS3_N_ENCAP_ERROR,
  .error_strings = etfs3_encap_error_strings,
#endif

};

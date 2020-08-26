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

#define ETFS3_TRANSMIT_MULTISEG 1 /* 1 = indirect multiseg, 0 = contig copy */
#define ETFS3_ENABLE_PADDING 1
#define ETFS3_PAD_INDIRECT 1	  /* but contig copy obviates */
#define ETFS3_TRACE_DECAP 0
#define ETFS3_RX_INTERFACE_REDIRECT 0	/* 1=old style, 0=l2xc */

#define DEDUCT_QUEUE_BYTES_PER_DATABLOCK 0

#define foreach_etfs3_next			\
_(INTERFACE_OUTPUT, "interface-output")
#if 0
_(MACSEC_ENCRYPT, "dpdk-macsec-encrypt")
#endif


/*
 * Canonical enum. Might be able to skip to save a lookup per pkt.
 * These values are indices to the next_nodes array in the node
 * registration structure.
 */
#define _(v, s) ETFS3_NEXT_##v,
typedef enum {
    foreach_etfs3_next
#undef _
    ETFS3_N_NEXT,
} etfs3_next_t;

static void
etfs3_decap_inc_simple_counter(etfs3_counter_enum ctr, u32 vm_thread_index,
			       u16 flow_index, u64 inc)
{
    vlib_simple_counter_main_t *scm;

    scm = vec_elt_at_index(etfs3_main.decap_simple_counters, ctr);
    vlib_increment_simple_counter(scm, vm_thread_index, flow_index, inc);
}

static void
etfs3_encap_inc_simple_counter(etfs3_counter_enum ctr, u32 vm_thread_index,
			       u16 flow_index, u64 inc)
{
    vlib_simple_counter_main_t *scm;

    scm = vec_elt_at_index(etfs3_main.encap_simple_counters, ctr);
    vlib_increment_simple_counter(scm, vm_thread_index, flow_index, inc);
}

static void
etfs3_decap_inc_combined_counter(etfs3_counter_enum ctr, u32 vm_thread_index,
				 u16 flow_index, u64 pkts, u64 bytes)
{
    vlib_combined_counter_main_t *cm;

    cm = vec_elt_at_index(etfs3_main.decap_combined_counters, ctr);
    vlib_increment_combined_counter(cm, vm_thread_index, flow_index, pkts,
				    bytes);
}

static void
etfs3_encap_inc_combined_counter(etfs3_counter_enum ctr, u32 vm_thread_index,
				 u16 flow_index, u64 pkts, u64 bytes)
{
    vlib_combined_counter_main_t *cm;

    cm = vec_elt_at_index(etfs3_main.encap_combined_counters, ctr);
    vlib_increment_combined_counter(cm, vm_thread_index, flow_index, pkts,
				    bytes);
}

static inline int
etfs3_alloc_buffer_indirect(vlib_main_t *vm, u32 *bi_new)
{
    vlib_buffer_t	*b;

    /*
     * TBD - fixme
     *
     * Initial adaptation to 2019 VPP will use the regular buffer
     * pool here instead of a special small-buffer pool. This
     * initial approach wastes 2KB per aggregated segment, but
     * the queue depths are probably small enough that it won't
     * be a problem. Defer use of a separate indirect pool until
     * functionality and performance are improved.
     */
    u32 n = vlib_buffer_alloc(vm, bi_new, 1);
    if (!n)
	return 0;

    ASSERT(n == 1);

    b = vlib_get_buffer(vm, *bi_new);

    /* debug code */
    ASSERT(b->ref_count > 0);

    ASSERT(!(b->flags & VLIB_BUFFER_INDIRECT));
    b->flags = 0;

    return n;
}

#if !ETFS3_PAD_INDIRECT
static inline int
etfs3_alloc_buffer_padding(vlib_main_t *vm, u32 *bi_new)
{
    int n = vlib_buffer_alloc(vm, bi_new, 1);
    if (n < 1)
	return n;

    ASSERT(n == 1);

    /* debug code */
    ASSERT(vlib_get_buffer(vm, *bi_new)->ref_count > 0);
    return n;
}
#endif

/*
 * IMPORTANT: One of the significant changes in the buffer model
 * from vpp-17 to vpp-19 has to do with how the  buffer free list
 * (from which buffers are allocated) is maintained.
 *
 * In vpp-17, dpdk maintained the free list. In the vpp-17 code,
 * vlib_buffer_free() ultimately called the dpdk rte_pktmbuf_free(),
 * which respected the various rte_mbuf semantics such as indirection
 * and reference counting.
 *
 * However, in vpp-19, the ultimate locus of control is shifted to
 * vpp. dpdk is used to initialize the free lists, but vpp handles
 * subsequent allocation/free on its own. dpdk can still do buffer
 * allocation/free, but at a low level it calls into the vpp free-list
 * management code. dpdk makes use of this latter path when, for
 * example, it frees buffers from am interface driver after transmit.
 *
 * Since etfs3 uses low-level dpdk semantics for indirect buffer
 * handling to support aggregation/fragmentation/reassembly, it MUST
 * free its buffers via the dpdk path in order to ensure reference
 * counts are honored. It should be safe to pass all "free" calls
 * through the dpdk path.
 */
static inline void
etfs3_buffer_free(vlib_main_t *vm, u32 *buffers, u32 n_buffers, const char * __clib_unused tag)
{
    /*
     * TBD can we make more efficient by pushing array handling to lower level?
     */
    while (n_buffers--) {

	vlib_buffer_t	*b;

	b = vlib_get_buffer(vm, *buffers);

	ASSERT(b->ref_count > 0);
	vlib_buffer_dpdk_free(vm, b);
	buffers++;
    }
}

static inline u8 *
vlib_buffer_indirect_data(vlib_buffer_t *b)
{
    if (b->flags & VLIB_BUFFER_INDIRECT) {
	vlib_buffer_t	*referenced;
	vlib_buffer_t	*guard1;
	vlib_buffer_t	*guard2;

	/*
	 * Obtain pointer to referenced buffer stashed by
	 * dpdk_buffer_attach()
	 */
	clib_memcpy(&guard1, b->data - sizeof(vlib_buffer_t *),
	    sizeof(vlib_buffer_t *));
	clib_memcpy(&guard2, b->data + sizeof(vlib_buffer_t *),
	    sizeof(vlib_buffer_t *));
	ASSERT(guard1 == b);
	ASSERT(guard2 == b);

	clib_memcpy(&referenced, b->data, sizeof(vlib_buffer_t *));
	return referenced->data;
    } else {
	return b->data;
    }
}

#if 0
static int
buffer_refers_to_pad_buffer(
    vlib_main_t			*vm,
    struct state_encap_flow	*ef,
    vlib_buffer_t		*b)
{
    vlib_buffer_t		*b_pad;

    b_pad = vlib_get_buffer(vm, ef->bi_padding_packet);

    u8 *pPadData = b_pad->data;

    u8 *pQueryData = vlib_buffer_indirect_data(b);

    return (pPadData == pQueryData);
}
#endif

void
free_vlib_buffer_chain(vlib_main_t *vm, vlib_buffer_t *b)
{
    if (!b)
	return;

    u32 b_ix = vlib_get_buffer_index(vm, b);
    etfs3_buffer_free(vm, &b_ix, 1, "f-fvbc");
}


#if ETFS3_TRANSMIT_MULTISEG
#define BUFFER_CHAIN_COMPACT(vm, need_compact, pBI, mtu) \
    ((need_compact)? buffer_chain_compact((vm),(pBI), (mtu)): 0)
#else
#define BUFFER_CHAIN_COMPACT(vm, need_compact, pBI, mtu) \
    buffer_chain_compact((vm),(pBI), (mtu))
#endif

/*
 * buffer_chain_compact() takes a multi-segment buffer chain representing
 * one packet and copies the data to a new single-segment buffer. The multi-
 * segment chain is freed and the new buffer is returned.
 *
 * This function is a temporary workaround for the pp2 ethernet driver that
 * does not handle multi-segment chains.
 *
 * !!! Also !!! In the case of indirect buffers, it makes them into
 * direct buffers, which allows them to be sent to nodes other than
 * dpdk interface-output.
 *
 * mtu parameter: ethernet payload limit; does not include 14-byte eth hdr
 */
static inline int
buffer_chain_compact(vlib_main_t *vm, u32 *bi_chain, u32 mtu)
{
    u32			bi_new;
    vlib_buffer_t	*b = vlib_get_buffer(vm, *bi_chain);

    /*
     * check degenerate case
     */
    if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT) &&
	!(b->flags & VLIB_BUFFER_INDIRECT)) {

	return 0;
    }

    /*
     * check length
     */
    u32	data_length = vlib_buffer_length_in_chain(vm, b);
    u32 total_length = data_length;

    ASSERT (data_length <= (mtu + sizeof(ethernet_header_t)));

    if (data_length < vlib_buffer_get_default_data_size (vm)) {
	/*
	 * Original algorithm: single segment
	 */

	u32 n_alloc = etfs3_alloc_buffer_indirect(vm, &bi_new);
	if (PREDICT_FALSE(n_alloc != 1)) {
	    return -1;
	}

	/*
	 * Copy header fields
	 */
	vlib_buffer_t	*d = vlib_get_buffer(vm, bi_new);

	d->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	d->current_data = 0;
	d->current_length = 0;
	d->total_length_not_including_first_buffer = 0;
	clib_memcpy (d->opaque, b->opaque, sizeof (b->opaque));

	while (b) {
	    u16	l;
	    u8	*src;
	    u8	*dst;

	    l = b->current_length;

	    dst = vlib_buffer_get_current(d) + d->current_length;

	    src = vlib_buffer_indirect_data(b) + b->current_data;

	    clib_memcpy (dst, src, l);
	    d->current_length += l;

	    b = vlib_get_next_buffer(vm, b);
	}
    } else {
	/*
	 * multiple segments
	 *
	 * This is newer code; after it is proven, we can probably
	 * use it always and delete the "Original algorithm: single segment"
	 * above.
	 */
	vlib_buffer_t	*b_src = vlib_get_buffer(vm, *bi_chain);
	vlib_buffer_t	*b_src_first = b_src;

	vlib_buffer_t	*b_dst_first = NULL;
	vlib_buffer_t	*b_dst;
	vlib_buffer_t	*b_dst_prev = NULL;


	u32		bi_dst_first = ~0u;
	u32		bi_dst;

	u32		src_avail;
	u16		src_offset;

	u32		dst_avail;
	u32		dst_offset;

	src_avail = b_src->current_length;
	src_offset = 0;

	dst_avail = 0;

	while (data_length) {
	    u32	len;

	    if (!src_avail) {
		b_src = vlib_get_next_buffer(vm, b_src);
		ASSERT(b_src);
		src_avail = b_src->current_length;
		src_offset = 0;
	    }

	    if (!dst_avail) {
		u32 n_alloc = etfs3_alloc_buffer_indirect(vm, &bi_dst);
		if (PREDICT_FALSE(n_alloc != 1)) {
		    free_vlib_buffer_chain(vm, b_dst_first);
		    return -1;
		}
		b_dst = vlib_get_buffer(vm, bi_dst);
		if (!b_dst_first) {
		    b_dst_first = b_dst;
		    bi_dst_first = bi_dst;
		}

		/* hook up "next" */
		if (b_dst_prev) {
		    b_dst_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
		    b_dst_prev->next_buffer = bi_dst;
		}
		b_dst_prev = b_dst;

		b_dst->flags = 0;
		b_dst->current_data = 0;
		b_dst->current_length = 0;

		dst_avail = vlib_buffer_get_default_data_size (vm);
		dst_offset = 0;
	    }

	    len = clib_min(src_avail, dst_avail);

	    clib_memcpy_fast(b_dst->data + dst_offset,
		vlib_buffer_indirect_data(b_src) + b_src->current_data +
		  src_offset,
		len);

	    b_dst->current_length += len;

	    dst_avail -= len;
	    src_avail -= len;
	    src_offset += len;
	    dst_offset += len;

	    data_length -= len;
	}
	/* copy opaque of head buffer (has tx interface id) */
	clib_memcpy (b_dst_first->opaque, b_src_first->opaque,
	    sizeof (b_src_first->opaque));


	b_dst_first->total_length_not_including_first_buffer =
	    total_length - b_dst_first->current_length;
	b_dst_first->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	bi_new = bi_dst_first;
    }

    /* free */
    etfs3_buffer_free(vm, bi_chain, 1, "f-comp");

    *bi_chain = bi_new;
    return 0;
}

#if 0
/*
 * Experiment: for each segment in chain, copy indirect data into
 * direct buffer and clear indirect flag. Detach the indirect buffer.
 *
 * Not intended for production code. This is just an experiment to
 * see if mvpp2 driver loses buffers if they are all direct.
 */
static inline void
buffer_chain_force_direct(
    vlib_main_t			*vm,
    struct state_encap_flow	*ef,
    u32				*bi_chain,
    u32				mtu)
{
    vlib_buffer_t	*b = vlib_get_buffer(vm, *bi_chain);

    /*
     * check degenerate case
     */
    if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT) &&
	!(b->flags & VLIB_BUFFER_INDIRECT)) {
	return;
    }

    for (; b; b = vlib_get_next_buffer(vm, b)) {
	if ((b->flags & VLIB_BUFFER_INDIRECT) &&
	    !buffer_refers_to_pad_buffer(vm, ef, b)) {

	    u8 *pSrc = vlib_buffer_indirect_data(b) + b->current_data;
	    u8 *pDst = b->data + b->current_data;
	    u16 len = b->current_length;

	    clib_memcpy_fast(pDst, pSrc, len);

	    vlib_buffer_detach(vm, b);
	}
    }
}
#endif

static void
flush_reasm_queue(vlib_main_t *vm, struct state_decap_flow *df)
{
    u32					*dropped_buffers = 0;
    datablock_reassembly_entry_t	dre;

    while (clib_fifo_elts(df->dr_fifo)) {
	clib_fifo_sub1(df->dr_fifo, dre);
	vec_add1(dropped_buffers, vlib_get_buffer_index(vm, dre.fragment));
    }
    if (dropped_buffers) {
	ETFS_DEBUG(DECAP, 1, "flush_reasm_queue: dropping %u frags\n",
	    vec_len(dropped_buffers));
	etfs3_buffer_free(vm, dropped_buffers, vec_len(dropped_buffers), "flreas");
    }
}

static int
cursor_set(
    vlib_main_t				*vm,
    vlib_buffer_t			*pkt,
    datablock_reassembly_cursor_t	*curs,
    u16					offset)
{
    vlib_buffer_t	*seg;
    u16			offset_current_seg;

    curs->pkt = pkt;

    for (seg = pkt, offset_current_seg = 0;
	seg;
	offset_current_seg += seg->current_length, seg = vlib_get_next_buffer(vm, seg)) {

	if ((offset >= offset_current_seg) &&
	    (offset < (offset_current_seg + seg->current_length))) {

	    curs->seg = seg;
	    curs->offset_current_seg = offset_current_seg;
	    curs->offset_in_seg = offset - offset_current_seg;
	    return 0;
	}
    }
    return -1;
}

static int
cursor_advance(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					increment)
{
    vlib_buffer_t	*seg;
    u16			offset;
    u16			offset_current_seg;

    offset_current_seg = curs->offset_current_seg;

    /* target offset */
    offset = offset_current_seg + curs->offset_in_seg + increment;

    for (seg = curs->seg; seg;
	offset_current_seg += seg->current_length, seg = vlib_get_next_buffer(vm, seg)) {


	if ((offset >= offset_current_seg) &&
	    (offset < (offset_current_seg + seg->current_length))) {

	    curs->seg = seg;
	    curs->offset_current_seg = offset_current_seg;
	    curs->offset_in_seg = offset - offset_current_seg;
	    return 0;
	}
    }
    return -1;
}

/*
 * format_buffer_data_at_cursor (&cursor, offset, count)
 * prints data in hex
 */
u8 *
format_buffer_data_at_cursor(u8 * s, va_list * args)
{
    datablock_reassembly_cursor_t	*cursor =
	va_arg (*args, datablock_reassembly_cursor_t *);
    int					offset = va_arg(*args, int);
    int					count = va_arg(*args, int);

    datablock_reassembly_cursor_t	c = *cursor;
    vlib_main_t	*vm = vlib_get_main();

    if (cursor_advance(vm, &c, offset))
	return format(s, "<<<");

    int	i = 0;
    while (count) {
	char	tag;
	char	*spacer;

	u8 *p = vlib_buffer_indirect_data(c.seg) + c.seg->current_data +
	    c.offset_in_seg;

	if (c.seg->flags & VLIB_BUFFER_INDIRECT)
	    tag = '_';
	else
	    tag = ' ';

	++i;
	if (i == 8)
	    spacer = "  ";
	else if (i == 16) {
	    i = 0;
	    spacer = "\n";
	} else {
	    spacer = "";
	}

	s = format(s, "%02x%c%s", *p, tag, spacer);
	if (cursor_advance(vm, &c, 1))
	    break;
	--count;
    }
    return s;
}

u8 *
format_buffer_data(u8 * s, va_list * args)
{
    vlib_buffer_t	*b = va_arg (*args, vlib_buffer_t *);
    int			count = va_arg(*args, int);

    datablock_reassembly_cursor_t	c;
    vlib_main_t				*vm = vlib_get_main();

    cursor_set(vm, b, &c, 0);

    int	i = 0;
    while (count) {
	char	tag;
	char	*spacer;

	u8 *p = vlib_buffer_indirect_data(c.seg) + c.seg->current_data +
	    c.offset_in_seg;

	if (c.seg->flags & VLIB_BUFFER_INDIRECT)
	    tag = '_';
	else
	    tag = ' ';

	++i;
	if (i == 8)
	    spacer = "  ";
	else if (i == 16) {
	    i = 0;
	    spacer = "\n";
	} else {
	    spacer = "";
	}

	s = format(s, "%02x%c%s", *p, tag, spacer);
	if (cursor_advance(vm, &c, 1))
	    break;
	--count;
    }
    return s;
}

/*
 * temporary, inefficient debugging tool
 */
u8 *
format_buffer_metadata(u8 * s, va_list * args)
{
    vlib_buffer_t	*b = va_arg (*args, vlib_buffer_t *);

    datablock_reassembly_cursor_t	c;
    vlib_main_t				*vm = vlib_get_main();
    vlib_buffer_t			*last_printed_seg_b = NULL;
    int					seg_count = 0;

    cursor_set(vm, b, &c, 0);

    while (1) {
	if (c.seg != last_printed_seg_b) {
	    char	di;

	    last_printed_seg_b = c.seg;

	    ++seg_count;
	    if (c.seg->flags & VLIB_BUFFER_INDIRECT)
		di = 'I';
	    else
		di = 'd';

	    s = format(s, "SEG %u: b=%p %c data %p, current_data %d\n",
		seg_count, c.seg, di, vlib_buffer_indirect_data(c.seg),
		c.seg->current_data);
	}

	if (cursor_advance(vm, &c, 1))
	    break;
    }
    return s;
}

/*
 * Returns 0 for success, otherwise malformed packet
 */
static int
getU16AtCursor(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					*val16bit)
{
    u8					*pMSB;
    u8					*pLSB;
    datablock_reassembly_cursor_t	c = *curs;

    /* we operate on our own copy of cursor, leave caller's cursor alone */

    pMSB = c.seg->data + c.seg->current_data + c.offset_in_seg;
    if (cursor_advance(vm, &c, 1))
	return -1;
    pLSB = c.seg->data + c.seg->current_data + c.offset_in_seg;

    /* network to host byte-order conversion happens here */
    *val16bit = *pMSB << 8 | *pLSB;

    return 0;
}

/*
 * Returns 0 for success, otherwise malformed packet
 */
static int
getMtduOffsetAtCursor(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					*MtduOffset)
{
    return getU16AtCursor(vm, curs, MtduOffset);
}

/*
 * Returns 0 for success, otherwise no more data in packet.
 *
 * Caller must check function return value and DbLength value.
 * If function return value is non-0, we are done with packet.
 * If function return value is 0 but DbLength is 0, we are done with packet.
 * Note that special case 1-octet padding causes function return value
 * to be non-0.
 */
static int
getDataBlockLengthAtCursor(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					*DbLength)
{
    return getU16AtCursor(vm, curs, DbLength);
}

/*
 * Cursor points into first packet in reassembly queue, at
 * length field of datablock.
 *
 * Normally returns 0. If non-0 is returned, something is
 * inconsistent with the reassembly queue and caller should flush it.
 */
static int
countUserFrameOctetsAtCursor(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					*ufOctets)
{
    u32	len = vlib_buffer_length_in_chain(vm, curs->pkt);
    u32	pos = 2 + curs->offset_current_seg + curs->offset_in_seg;

    if (len >= pos) {
	u32	difference = len - pos;

	/* Don't allow overflow into 16-bit calculated value */
	if (difference > 0xffff) {
	    /* Shouldn't happen. Something is b0rked. */
	    return -1;
	}

	*ufOctets = len - pos;
    } else {
	return -1;
    }
    return 0;
}

/*
 * Make an indirect mbuf chain referencing the User Frame starting
 * at the cursor and extending for DataBlockLength octets.
 *
 * Does NOT adjust cursor.
 *
 * Returns pointer to user frame or NULL if no memory
 */
static vlib_buffer_t *
getUserFrameAtCursor(
    vlib_main_t				*vm,
    struct state_decap_flow		* __clib_unused fd,
    datablock_reassembly_cursor_t	*curs,
    u16					DataBlockLength,
    vlib_buffer_t			**seg_last)
{
    vlib_buffer_t			*uf = NULL;
    u16					nseg = 0;
    u32					pktlen = 0;

    vlib_buffer_t			*seg_src;
    vlib_buffer_t			*seg_dst;
    vlib_buffer_t			*seg_dst_prev = NULL;

    /*
     * Cursor of packet should be pointing to start of UF data.
     */
    u16	octets_to_copy;

    if (seg_last && *seg_last)
	seg_dst_prev = *seg_last;

    for (seg_src = curs->seg, octets_to_copy = DataBlockLength;
	seg_src && octets_to_copy;
	seg_src = vlib_get_next_buffer(vm, seg_src)) {

	u32	n_alloc;
	u32	seg_dst_ix;

	n_alloc = etfs3_alloc_buffer_indirect(vm, &seg_dst_ix);

	if (n_alloc != 1) {
	    free_vlib_buffer_chain(vm, uf);
	    return NULL;
	}

	seg_dst = vlib_get_buffer(vm, seg_dst_ix);
	seg_dst->flags |= VLIB_BUFFER_EXT_HDR_VALID;
	vlib_buffer_attach(vm, seg_dst, seg_src);
	++nseg;

	/* first segment in fragment with data: offset_in_seg matters */
	if (seg_src == curs->seg) {

	    /* first segment in fragment with data: offset_in_seg matters */
	    seg_dst->current_data = seg_src->current_data +
		curs->offset_in_seg;
	    seg_dst->current_length = seg_src->current_length -
		curs->offset_in_seg;

	} else {

	    seg_dst->current_data = seg_src->current_data;
	    seg_dst->current_length = seg_src->current_length;
	}

	if (octets_to_copy < seg_dst->current_length) {
	    seg_dst->current_length = octets_to_copy;
	}

	pktlen += seg_dst->current_length;
	octets_to_copy -= seg_dst->current_length;

	if (!uf) {
	    uf = seg_dst;
	}

	if (seg_dst_prev) {
	    seg_dst_prev->next_buffer = seg_dst_ix;
	    seg_dst_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	}

	seg_dst_prev = seg_dst;
    }

    if (seg_last)
	*seg_last = seg_dst_prev;
    return uf;
}



/*
 * Part of receive decapsulation.
 *
 * Expects cursor to point to start of DataBlock, including length field.
 *
 * DataBlockLength is the value read from the packet
 *
 * Examines only the packet the cursor points to.
 * returns 0 when done, non-0 when not done.
 *
 * If we return 0, we are responsible for either queueing the packet
 * referenced by the cursor, or freeing it.
 */
static int
processDataBlockAtCursor(
    vlib_main_t				*vm,
    //vlib_node_runtime_t			* __clib_unused node,
    vlib_node_runtime_t			*node_runtime,
    struct state_decap_flow		*df,
    datablock_reassembly_cursor_t	*curs,
    u16					MtduOffset,
    u16					DataBlockLength,
    u32					**pToNext,
    u32					*pNLeftToNext)
{
    if (!DataBlockLength) {
	/* only padding remains: done with packet */
	free_vlib_buffer_chain(vm, curs->pkt);
	return 0;
    }

    /*
     * If there are at least DataBlockLength octets remaining,
     * form user packet
     */
    u16	unparsed_octets;

    unparsed_octets = vlib_buffer_length_in_chain(vm, curs->pkt) -
	curs->offset_current_seg - curs->offset_in_seg - 2;

    if (unparsed_octets >= DataBlockLength) {
	vlib_buffer_t	*u;

	cursor_advance(vm, curs, 2);
	u = getUserFrameAtCursor(vm, df, curs, DataBlockLength, NULL);

	if (u) {
	    /* transmit this user frame */

	    if (!*pNLeftToNext) {
		/* no room in destination frame, drop */
		etfs3_decap_inc_simple_counter(ETFS3_COUNTER_NB_DROP_NEXT_FRAME_FULL,
					       vm->thread_index, df->index, 1);
		free_vlib_buffer_chain(vm, u);
	    } else {
		vnet_buffer(u)->sw_if_index[VLIB_TX] = df->if_index_tx;
		u32	ix = vlib_get_buffer_index(vm, u);

		/* write new packet buffer index to frame buffer array slot */
		if (BUFFER_CHAIN_COMPACT(vm, !(df->tx_port_is_dpdk), &ix, df->tx_mtu)) {
		    etfs3_decap_inc_simple_counter(ETFS3_COUNTER_NB_DROP_NEXT_OOM,
						   vm->thread_index, df->index, 1);
		    free_vlib_buffer_chain(vm, u);
		} else {
		    ETFS_DEBUG(DECAP, 1,
			"processDataBlockAtCursor: send pkt %lu bytes\n",
			vlib_buffer_length_in_chain(vm, u));
		    uword nbytes = vlib_buffer_length_in_chain(vm, u);
		    etfs3_decap_inc_combined_counter(ETFS3_COUNTER_TX,
						     vm->thread_index,
						     df->index, 1, nbytes);

		    /* debug: show outgoing dst ethaddr */
		    ETFS_DEBUG_F(DECAP, 5,
			"%s: eth hdr: %U\n%c",
			__func__,
			format_buffer_data, u, 14,
			0);

#if ETFS3_TRACE_DECAP
		    u32 next_index = ETFS3_NEXT_INTERFACE_OUTPUT;
		    vlib_trace_buffer(vm, node_runtime, next_index,
			u, 1 /* follow chain */);
#endif
		    **pToNext = ix;
		    *pToNext += 1;
		    *pNLeftToNext -= 1;
		}
	    }
	} else {
	    etfs3_decap_inc_simple_counter(ETFS3_COUNTER_NB_DROP_TX_OOM,
					   vm->thread_index, df->index, 1);
	}

	/* skip past datablock just processed */
	if (cursor_advance(vm, curs, DataBlockLength)) {
	    /* only padding remains: done with packet */
	    free_vlib_buffer_chain(vm, curs->pkt);
	    return 0;
	}

	return 1; /* more octets to process */

    } else {
	/*
	 * Put rest of packet on reassembly queue.
	 */
	datablock_reassembly_entry_t	dre;

	dre.fragment = curs->pkt;
	dre.mtdu_offset = MtduOffset;
	dre.db_length = DataBlockLength;
	dre.cursor = *curs;
	/* queue was cleared above: 'dre' becomes only entry */
	clib_fifo_add1(df->dr_fifo, dre);
	etfs3_decap_inc_simple_counter(ETFS3_COUNTER_PKT_FRAGMENT_RX,
				       vm->thread_index, df->index, 1);

	return 0;
    }

    ASSERT(0);	/* shouldn't reach this point */
}

/*
 * Construct a user frame from the reassembly queue and the first
 * part of the tail packet.
 *
 * Note that the reassembly queue starts at the 2-byte MTDU lengh field
 *
 * Does NOT adjust cursor: caller must do that afterward.
 */
static vlib_buffer_t *
reassemble_one(
    vlib_main_t				*vm,
    struct state_decap_flow		*df,
    datablock_reassembly_cursor_t	*curs_tail_pkt,
    u16					tail_uf_length)
{
    vlib_buffer_t			*uf = NULL;
    vlib_buffer_t			*seg_dst_prev = NULL;
    int first = 1;

    datablock_reassembly_entry_t	*dre;

    clib_fifo_foreach(dre, df->dr_fifo, ({
	datablock_reassembly_cursor_t	cursor;
	vlib_buffer_t			*tmp;

	cursor = dre->cursor;

	if (first) {
	    /* skip DataBlock length field when constructing output pkt */
	    cursor_advance(vm, &cursor, 2);
	    first = 0;
	}

	tmp = getUserFrameAtCursor(vm, df, &cursor, (u16)-1, &seg_dst_prev);
	if (tmp == NULL) {
		etfs3_decap_inc_simple_counter(ETFS3_COUNTER_PKT_FRAGMENT_RX_DROP,
					       vm->thread_index, df->index, 1);
		ETFS_DEBUG(DECAP, 1, "reassemble_one: OOM\n");

		/* Buffers may have been added to the chain and then freed.
		 * Only free buffers that haven't been already.
		 */
		if (seg_dst_prev) {
		    seg_dst_prev->next_buffer = 0;
		    seg_dst_prev->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		    free_vlib_buffer_chain(vm, uf);
		}
		flush_reasm_queue(vm, df);
		return NULL;
	}
	if (!uf)
	    uf = tmp;
    }));


    vlib_buffer_t	*tail_copy;

    /*
     * Get chain of indirect bufs with tail. Does NOT adjust cursor
     */
    tail_copy = getUserFrameAtCursor(vm, df, curs_tail_pkt, tail_uf_length, NULL);

    if (!tail_copy) {
	etfs3_decap_inc_simple_counter(ETFS3_COUNTER_PKT_FRAGMENT_RX_DROP,
				       vm->thread_index, df->index, 1);
	ETFS_DEBUG(DECAP, 1, "reassemble_one: tail_copy is NULL\n");
	free_vlib_buffer_chain(vm, uf);
	free_vlib_buffer_chain(vm, tail_copy);
	flush_reasm_queue(vm, df);
	return NULL;
    }

    seg_dst_prev->next_buffer = vlib_get_buffer_index(vm, tail_copy);
    seg_dst_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;

    ETFS_DEBUG(DECAP, 1,
	"reassemble_one: have tail_copy, normal flush follows\n");
    flush_reasm_queue(vm, df);

    return uf;
}

typedef struct
{
    u8	is_macsec;
} decap_rx_runtime_data_t;

/*
 * decap_rx_node_fn() should be registered to receive packets from
 * any interface with ethertype 0x8552.
 */
static uword
decap_rx_node_fn (
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_frame_t	*frame)
{
    u32					*dropped_buffers = 0;

    u16					MtduOffset;
    datablock_reassembly_cursor_t	cursor;

    /* This group is related to the frame of incoming packets */
    u32					n_left_from;
    u32					*from;

    /* This group is related to sending packts to the next node */
    u32					*to_next;
    u32					n_left_to_next;
    u32					next_index;

    next_index = ETFS3_NEXT_INTERFACE_OUTPUT;

    /* There is only one next node: interface-output */
    /*
     * Sets to_next to point to u32 that should receive index of packet
     * Sets n_left_to_next to number of slots available
     */
    vlib_get_next_frame(vm, node, ETFS3_NEXT_INTERFACE_OUTPUT,
	to_next, n_left_to_next);

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    BVT(clib_bihash)	*pDecapFlowTable;

    pDecapFlowTable =
	((decap_rx_runtime_data_t *)(node->runtime_data))->is_macsec ?
	    &etfs3_main.decap_flow_table_macsec:
	    &etfs3_main.decap_flow_table;

    ETFS_DEBUG(DECAP, 1, "decap: rx %u, is_macsec: %u\n",
	n_left_from,
	((decap_rx_runtime_data_t *)(node->runtime_data))->is_macsec);

    while (n_left_from > 0)
    {
	/*
	 * First implementation handles 1 packet at a time
         */
        u32			bi0;
	vlib_buffer_t		*b0;
        u32			sw_if_index0;

	bi0 = from[0];		/* u32 index identifies buffer */
	from += 1;
	n_left_from -= 1;

	b0 = vlib_get_buffer (vm, bi0);/* buffer pointer from index */

	/* buffer has field indicating which interface index it arrived on */
        sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	/*
	 * Look up decap flow & state based on received interface.
	 * See vnet/l2/l2_fib.h'l2fib_valid_swif_seq_num for example.
	 */
	BVT (clib_bihash_kv) kv;
	kv.key = sw_if_index0;
	if (BV (clib_bihash_search)(pDecapFlowTable, &kv, &kv)) {
	    /* no per-interface config: discard packet */
	    /* TBD re-inject into generic receive path */
	    vec_add1(dropped_buffers, bi0);
	    ETFS_DEBUG(DECAP, 1, "decap: interface index %u: no match\n",
		sw_if_index0);
	    continue;
	}
	struct state_decap_flow	*df = (struct state_decap_flow *)(kv.value);
	vlib_simple_counter_main_t *scm;

	etfs3_decap_inc_combined_counter(ETFS3_COUNTER_RX,
					 etfs3_main.vlib_main->thread_index,
					 df->index, 1,
					 vlib_buffer_length_in_chain(vm, b0));

	scm = vec_elt_at_index(etfs3_main.decap_simple_counters,
			       ETFS3_COUNTER_PKT_RX_DROP_MALFORMED);

	/* VPP ethernet layer advances start of buffer data to after l2 hdr */
	if (cursor_set(vm, b0, &cursor, 0)) {
	    /* malformed */
	    vlib_increment_simple_counter(scm, vm->thread_index, df->index, 1);
	    vec_add1(dropped_buffers, bi0);
	    ETFS_DEBUG(DECAP, 1, "decap: malformed 1\n");
	    continue;
	}

	if (getMtduOffsetAtCursor(vm, &cursor, &MtduOffset)) {
	    /* malformed */
	    vlib_increment_simple_counter(scm, vm->thread_index, df->index, 1);
	    vec_add1(dropped_buffers, bi0);
	    ETFS_DEBUG(DECAP, 1, "decap: malformed 2\n");
	    continue;
	}

	/* advance past offset field */
	if (cursor_advance(vm, &cursor, 2)) {
	    /* malformed */
	    vlib_increment_simple_counter(scm, vm->thread_index, df->index, 1);
	    vec_add1(dropped_buffers, bi0);
	    ETFS_DEBUG(DECAP, 1, "decap: malformed 3\n");
	    continue;
	}
	ETFS_DEBUG(DECAP, 1, "decap: MtduOffset %u\n", MtduOffset);

	if (MtduOffset == 0) {
	    /*
	     * Free any pending datablocks
	     */
	    if (clib_fifo_elts(df->dr_fifo)) {
		    /* reassembly fifo not empty, so a fragmented MSDU will
		     * be dropped.
		     */
		    etfs3_decap_inc_simple_counter(ETFS3_COUNTER_PKT_FRAGMENT_RX_DROP,
						   vm->thread_index, df->index, 1);
		    flush_reasm_queue(vm, df);
	    }

	    u16	DataBlockLength;
	    int	freeit = 1;

	    while (getDataBlockLengthAtCursor(vm, &cursor, &DataBlockLength) == 0) {

		int more = processDataBlockAtCursor(vm, node, df, &cursor,
		    MtduOffset, DataBlockLength, &to_next, &n_left_to_next);

		if (!more) {
		    /* already freed, don't do it again */
		    freeit = 0;
		    break;
		}
	    }

	    if (freeit) {
		vec_add1(dropped_buffers, bi0);
	    }
	    continue;
	}

	/* MtduOffset is non-0 */

	/*
	 * Validate fragment
	 */

	if (!clib_fifo_elts(df->dr_fifo)) {
	    /*
	     * no preceding fragments: missed or out-of-order frame: advance
	     * to next length field, if it is in this packet
	     */
	    etfs3_decap_inc_simple_counter(ETFS3_COUNTER_PKT_FRAGMENT_RX_DROP,
					   vm->thread_index, df->index, 1);
	    if (cursor_advance(vm, &cursor, MtduOffset)) {
		/* malformed */
		vec_add1(dropped_buffers, bi0);
		ETFS_DEBUG(DECAP, 1, "decap: malformed A1\n");
		continue;
	    }
	    ETFS_DEBUG(DECAP, 1, "decap: goto start_length_and_user_frame\n");
	    goto start_length_and_user_frame;
	}

	datablock_reassembly_entry_t	*dre_first;
	u16				userframe_octets_queued;

	dre_first = clib_fifo_elt_at_index(df->dr_fifo, 0);

	/* compute user frame octets in queue */

	/* first packet in queue */
	if (countUserFrameOctetsAtCursor(vm, &dre_first->cursor,
	    &userframe_octets_queued)) {

	    flush_reasm_queue(vm, df);
	    /*
	     * TBD this is not optimal: if newpkt contains start of next UF,
	     * we should just advance cursor to that point and start there.
	     * Punt for now as we don't expect to reach here in the first place.
	     */
	    ETFS_DEBUG(DECAP, 1, "decap_rx_node_fn: ugh\n");
	    vec_add1(dropped_buffers, bi0);
	    continue;
	}

	ETFS_DEBUG(DECAP, 1, "decap: %u userframe octets in first pkt\n",
	    userframe_octets_queued);

	/*
	 * The reassembly queue packets after the first, if any, will contain
	 * only octets belonging to the single DataBlock we are trying to
	 * reassemble (otherwise the first DataBlock would have been
	 * reassembled previously).
	 *
	 * Therefore, we count all the octets of non-first packets in the
	 * reassembly queue, less the ethernet headers and MTDU offset fields.
	 *
	 * TBD can probably optimize this by keeping a running count
	 */
	datablock_reassembly_entry_t	*f;

	clib_fifo_foreach(f, df->dr_fifo, ({
	    if (f != dre_first) {
		u16 userframe_length;

		/* NB vpp eats ethernet header on receive */
		userframe_length =
		    (((datablock_reassembly_entry_t *)f)->fragment->current_length
		    - 2);				/* MTDU offset field */
		ETFS_DEBUG(DECAP, 1,
		    "decap: counting non-1st frag UF length %u\n",
		    userframe_length);
		userframe_octets_queued += userframe_length;
	    }
	}));

	ETFS_DEBUG(DECAP, 1,
	    "decap: %u userframe octets in first pkt + remaining queued\n",
	    userframe_octets_queued);

	if (MtduOffset != (dre_first->db_length - userframe_octets_queued)) {
	    /* offset doesn't match expected value: missed or ooo frame: skip */

	    ETFS_DEBUG(DECAP, 1,
		"decap: MtduOffset doesn't match expected value %d\n",
		(dre_first->db_length - userframe_octets_queued));


	    /*
	     * Free any pending datablocks
	     */
	    flush_reasm_queue(vm, df);

	    if (cursor_advance(vm, &cursor, MtduOffset)) {
		/* malformed */
		vec_add1(dropped_buffers, bi0);
		continue;
	    }
	    goto start_length_and_user_frame;
	}

	/*
	 * Reaching here means that MTDU offset is non-0 and that its value
	 * is consistent with the data length(s) of the prior fragments in
	 * the reassembly queue.
	 */

	ETFS_DEBUG(DECAP, 1,
	    "decap: MTDU offset non-0 and value consistent with reasm q\n");

	/*
	 * If the new packet does not complete the fragmented DataBlock,
	 * then add it to the reassembly queue and return (done with packet)
	 *
	 * If this new packet completes the fragmented DataBlock,
	 * reassemble and send. Then look for more Datablocks in
	 * the packet and dispatch and/or save for reassembly.
	 */

	u16	possible_datablock_octets;

	/* NB VPP already ate the ethernet header */
	possible_datablock_octets =
	    vlib_buffer_length_in_chain(vm, b0) - 2; /* -2 for MtduOffset */

	ETFS_DEBUG(DECAP, 1, "decap: possible_datablock_octets %u\n",
	    possible_datablock_octets);

	if (MtduOffset > possible_datablock_octets) {
	    ETFS_DEBUG(DECAP, 1,
		"decap: enough datablock octets; add to reasm q\n");

	    /*
	     * Not enough datablock octets. New packet does not complete
	     * the fragmented DataBlock: add to reassembly queue and return.
	     */
	    datablock_reassembly_entry_t dre;

	    dre.fragment = cursor.pkt;
	    dre.mtdu_offset = MtduOffset;
	    dre.db_length = 0;		/* not 1st packet in reassembly queue */
	    dre.cursor = cursor;

	    clib_fifo_add1(df->dr_fifo, dre);
	    continue;
	}

	vlib_buffer_t	*u;

	/* does not adjust cursor */
	u = reassemble_one(vm, df, &cursor, MtduOffset);

	/* send user frame */

	/* write new packet buffer index to frame buffer array slot */
	if (u) {
	    if (n_left_to_next) {
		vnet_buffer(u)->sw_if_index[VLIB_TX] = df->if_index_tx;
		u32 ix = vlib_get_buffer_index(vm, u);
		if (BUFFER_CHAIN_COMPACT(vm, !(df->tx_port_is_dpdk), &ix, df->tx_mtu)) {
		    etfs3_decap_inc_simple_counter(ETFS3_COUNTER_NB_DROP_DECODE_OOM,
						   vm->thread_index, df->index, 1);
		    vec_add1(dropped_buffers, vlib_get_buffer_index(vm, u));
		} else {
		    uword nbytes = vlib_buffer_length_in_chain(vm, vlib_get_buffer(vm, ix));

		    nbytes =
			vlib_buffer_length_in_chain(vm, vlib_get_buffer(vm, ix));
		    etfs3_decap_inc_combined_counter(ETFS3_COUNTER_TX,
						     vm->thread_index,
						     df->index, 1, nbytes);

		    ETFS_DEBUG(DECAP, 1, "reassemble_one: send pkt %lu bytes\n",
			nbytes);
#if ETFS3_TRACE_DECAP
		    vlib_trace_buffer(vm, node, next_index,
			vlib_get_buffer(vm, ix), 1 /* follow chain */);
#endif
		    *to_next = ix;
		    to_next += 1;
		    n_left_to_next -= 1;
		}
	    } else {
		etfs3_decap_inc_simple_counter(ETFS3_COUNTER_NB_DROP_DECODE_TX,
					       vm->thread_index, df->index, 1);
		vec_add1(dropped_buffers, vlib_get_buffer_index(vm, u));
	    }
	}

	if (cursor_advance(vm, &cursor, MtduOffset)) {
	    vec_add1(dropped_buffers, bi0);
	    continue;
	}

	u16	DataBlockLength;
	int	freeit;

start_length_and_user_frame:
	freeit = 1;
	/* loop over remaining datablocks in packet */
	while (getDataBlockLengthAtCursor(vm, &cursor, &DataBlockLength) == 0) {

	    int more = processDataBlockAtCursor(vm, node, df, &cursor,
		MtduOffset, DataBlockLength, &to_next, &n_left_to_next);

	    if (!more) {
		/* already freed, don't do it again */
		freeit = 0;
		break;
	    }
	}

	if (freeit)
	    vec_add1(dropped_buffers, bi0);
    }

    vlib_put_next_frame(vm, node, next_index, n_left_to_next);

    if (dropped_buffers)
	etfs3_buffer_free(vm, dropped_buffers, vec_len(dropped_buffers),
	    "f-drn");

    return frame->n_vectors;
}

struct state_encap_flow *
encap_flow_get(
    u16			encap_rxport)	/* rx port of flow to look up */
{
    /*
     * Look up encap state for the flow based on received interface.
     * See vnet/l2/l2_fib.h'l2fib_valid_swif_seq_num for example.
     */
    BVT (clib_bihash_kv) kv;
    kv.key = encap_rxport;
    if (BV (clib_bihash_search)(&etfs3_main.encap_flow_table, &kv, &kv)) {
	return NULL;
    }
    return (struct state_encap_flow *)(kv.value);
}

struct state_decap_flow *
decap_flow_get(
    u16		decap_rxport,	/* rx port of flow to look up */
    bool	encrypted)	/* selected encrypted/plain flow on this port */
{
    BVT (clib_bihash_kv)	search;
    BVT (clib_bihash_kv)	result;
    BVT(clib_bihash)		*pDecapFlowTable;

    pDecapFlowTable = encrypted?
	&etfs3_main.decap_flow_table_macsec:
	&etfs3_main.decap_flow_table;

    search.key = decap_rxport;
    if (!BV(clib_bihash_search)(pDecapFlowTable, &search, &result))
	return (struct state_decap_flow *)result.value;

    return NULL;
}

typedef struct
{
    u8 src[6];
    u8 dst[6];
    u32 sw_if_index;
    u32 buffer_length;
} encap_rx_trace_t;

static u8 *
format_encap_rx_trace(u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    encap_rx_trace_t *t = va_arg (*args, encap_rx_trace_t *);

    s = format (s, "encap_rx: sw_if_index %d dst %U src %U totlen %u",
	t->sw_if_index,
	format_ethernet_address, t->dst,
	format_ethernet_address, t->src,
	t->buffer_length);
    return s;
}

/*
 * encap_rx_node_fn() should be called on-demand with batches of
 * received packets.
 */
static uword
encap_rx_node_fn (
    vlib_main_t		*vm,
    vlib_node_runtime_t	* node,
    vlib_frame_t	*frame)
{
    u32			n_left_from;
    u32			*from;
    u32			*dropped_buffers = 0;
    int			do_trace = 0;

    char		*myname = "encap_rx_node_fn";	/* debug */

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	do_trace = 1;

    ETFS_DEBUG(ENCAP_RX, 1, "%s: n_left_from: %u\n", myname, n_left_from);

    while (n_left_from > 0)
    {
	/*
	 * First implementation handles 1 packet at a time
        */
        u32			bi0;
	vlib_buffer_t		*b0;
        u32			sw_if_index0;
	u64			queue_delay;
	u64			bytes_enqueued;
	u32			b0_bytes;

	bi0 = from[0];		/* u32 index identifies buffer */
	from += 1;
	n_left_from -= 1;

	b0 = vlib_get_buffer (vm, bi0);/* buffer pointer from index */
	b0_bytes = vlib_buffer_length_in_chain(vm, b0);

	/* buffer has field indicating which interface index it arrived on */
        sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	if (do_trace) {
	    ethernet_header_t *h0 = vlib_buffer_get_current (b0);
	    encap_rx_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	    t->sw_if_index = sw_if_index0;
	    t->buffer_length = b0_bytes;
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
	    vec_add1(dropped_buffers, bi0);
	    continue;
	}
	struct state_encap_flow	*ef = (struct state_encap_flow *)(kv.value);

	etfs3_encap_inc_combined_counter(ETFS3_COUNTER_RX, vm->thread_index,
					 ef->index, 1, b0_bytes);

	/* transmit queue depth is ef->encap_db_bytes_enqueued */
	bytes_enqueued = __atomic_load_n(&ef->encap_db_bytes_enqueued, __ATOMIC_SEQ_CST);
	queue_delay = bytes_enqueued * 8 * 1000 / ef->tx_rate_bits_msec;

	ETFS_DEBUG(ENCAP_RX, 1,
	    "%s: prior queue depth: %lu bytes, ", myname, bytes_enqueued);

	if (queue_delay < ef->max_aggr_time_bounded_usec) {
	    /* OK to enqueue */

	    ETFS_DEBUG(ENCAP_RX, 1, "ok to enqueue\n");

	    /*
	     * assume mbuf has 2 bytes headroom for
	     * datablock len field
	     */
	    u32 newbytes = b0_bytes;

	    /* insert DataBlock length field. XXX Assume 2-byte alignment */
	    u16 *pLen = (u16 *)vlib_buffer_push_uninit(b0, 2);
	    *pLen = clib_host_to_net_u16(newbytes);

	    newbytes += 2;

	    /*
	     * Keep track of queue depth in bytes. Don't need the
	     * return value here.
	     */
	    __atomic_add_fetch(&ef->encap_db_bytes_enqueued, newbytes, __ATOMIC_SEQ_CST);

	    /* queue to fixed-rate transmitter */
	    clib_spinlock_lock(&ef->lock);
	    clib_fifo_add1(ef->datablock_fifo, bi0);
	    clib_spinlock_unlock(&ef->lock);

	    etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_QUEUED,
					   vm->thread_index, ef->index, 1);

#if 0
	    /* debug: show data */
	    {
		u8	*s;
		s = format(0, "%s: enqueued %U,\n  %U\n%c", myname,
		    format_vlib_buffer, b0,
		    format_hex_bytes,
		      vlib_buffer_get_current (b0), b0->current_length, 0);
		printf("%s", s);
		vec_free(s);
	    }
#endif
	} else {
	    etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_DROP_QUEUE_DELAY,
					   vm->thread_index, ef->index, 1);
	    ETFS_DEBUG(ENCAP_RX, 1, "full, drop\n");
	    vec_add1(dropped_buffers, bi0);
	}
    }

    if (dropped_buffers)
	etfs3_buffer_free(vm, dropped_buffers, vec_len(dropped_buffers),
	    "f-d-ern");

    return frame->n_vectors;
}

/*
 * Make a chain of mbuf segments encoding one outgoing MTDU,
 * possibly limited by space remaining in the caller's packet.
 *
 * Caller must allocate initial 2-byte offset field at start of MTDU
 *
 * We will allocate indirect datablock fragment(s) for one DataBlock.
 * Note that the length fields are already part of the DataBlocks
 *
 * Caller must append padding if bytes_out_remaining <= 2 or no more DataBlocks
 */
static int
tx_add_datablock(
    vlib_main_t			*vm,
    struct state_encap_flow	*ef,
    /* vlib_buffer_t		*pkt_in, */ /* use ef->encap_db_current_index */
    u16				bytes_out_remaining, /* to fill packet */
    u32				*chain_head_index,
    u32				*chain_tail_index,
    u16				*offset_in_new)	/* new value upon return */
{

    char			*myname = "tx_add_datablock";
    vlib_buffer_t		*seg_in_b;
    vlib_buffer_t		*seg_out_b = NULL;
    vlib_buffer_t		*seg_out_first_b = NULL;
    vlib_buffer_t		*seg_out_prev_b = NULL;
    u16				offset_in;	/* where to start in pkt_in */
    u16				offset_of_seg_in;
    u16				pos_in_seg_in;
    u32				seg_in_ix;
    u32				seg_out_ix = INDEX_INVALID;
    u32				seg_out_first_ix = INDEX_INVALID;
    u16				offset_in_cur = 0;

    /* Point to current datablock we're processing */
    seg_in_ix = ef->encap_db_current_index;
    seg_in_b = vlib_get_buffer(vm, seg_in_ix);

    /* Compute offset into datablock to encode next */
    offset_in = offset_in_cur =
	vlib_buffer_length_in_chain(vm, seg_in_b) - ef->encap_db_bytes_remaining;

    /*
     * Advance to the correct spot in the input chain
     */
    offset_of_seg_in = 0;
    while (offset_in > offset_of_seg_in + seg_in_b->current_length) {
	if (seg_in_b->flags & VLIB_BUFFER_NEXT_PRESENT) {
	    offset_of_seg_in += seg_in_b->current_length;
	    seg_in_ix = seg_in_b->next_buffer;
	    seg_in_b = vlib_get_buffer(vm, seg_in_ix);
	} else {
	    /* offset exceeds available data */
	    ETFS_DEBUG(190802, 1,
		"tx_add_datablock: offset exceeds available data\n");
	    return -EINVAL;
	}
    }
    pos_in_seg_in = offset_in - offset_of_seg_in;

    /*
     * While there is room in the output packet, add input segments
     *
     * TBD optimize by pre-counting and allocating new buffers all at once
     */
    while (seg_in_b && bytes_out_remaining) {
	u16	len;
	u32	n_alloc;

	if (seg_out_b) {
	    seg_out_prev_b = seg_out_b;
	}

	n_alloc = etfs3_alloc_buffer_indirect(vm, &seg_out_ix);
	if (PREDICT_FALSE(n_alloc != 1)) {
	    if (seg_out_first_b)
		etfs3_buffer_free(vm, &seg_out_first_ix, 1, "f-tad");
	    ETFS_DEBUG(190802, 1, "tx_add_datablock: n_alloc: %u\n", n_alloc);
	    return -ENOMEM;
	}
	seg_out_b = vlib_get_buffer(vm, seg_out_ix);
	ETFS_DEBUG(190802, 1, "%s: allocated indirect ix %u, b %p\n",
	    myname, seg_out_ix, seg_out_b);
	seg_out_b->flags |= VLIB_BUFFER_EXT_HDR_VALID;

	if (!seg_out_first_b) {
	    seg_out_first_b = seg_out_b;
	    seg_out_first_ix = seg_out_ix;
	}
	if (seg_out_prev_b) {
	    seg_out_prev_b->next_buffer = seg_out_ix;
	    seg_out_prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	}

	/* debug: show incoming buffer */
	ETFS_DEBUG_F(190802, 2,
	    "%s: pos_in_seg_in: %u, seg_in_b: %U,\n  %U\n%c",
	    myname,
	    pos_in_seg_in,
	    format_vlib_buffer, seg_in_b,
	    format_buffer_data, seg_in_b, seg_in_b->current_length, 0);

	len = bytes_out_remaining;
	if (len > seg_in_b->current_length - pos_in_seg_in)
	    len = seg_in_b->current_length - pos_in_seg_in;

	ETFS_DEBUG(190802, 2, "%s: bytes_out_remaining %u, len %u\n",
	    myname, bytes_out_remaining, len);

	vlib_buffer_attach(vm, seg_out_b, seg_in_b);
	seg_out_b->current_data = seg_in_b->current_data + pos_in_seg_in;
	seg_out_b->current_length = len;

	ETFS_DEBUG(190802, 1,
	    "%s: seg_in_b %p, seg_in_b->current_data %d, seg_in_b->current_length %u\n",
	    myname, seg_in_b, seg_in_b->current_data, seg_in_b->current_length);
	ETFS_DEBUG(190802, 1, "%s: pos_in_seg_in %u\n", myname, pos_in_seg_in);
	ETFS_DEBUG(190802, 1,
	    "%s: seg_out_b %p, seg_out_b->current_data %d, seg_out_b->current_length %u\n",
	    myname, seg_out_b, seg_out_b->current_data, seg_out_b->current_length);

	ETFS_DEBUG_F(190802, 2,
	    "%s: seg_out_b: %U\n  %U\n%c",
	    myname,
	    format_vlib_buffer, seg_out_b,
	    format_buffer_data, seg_out_b, seg_out_b->current_length, 0);

	if (seg_out_first_b == seg_out_b) {
	    seg_out_first_b->total_length_not_including_first_buffer = 0;
	} else {
	    seg_out_first_b->total_length_not_including_first_buffer += len;
	}

	offset_in_cur += len;	/* So we can tell caller how much consumed */

#if !DEDUCT_QUEUE_BYTES_PER_DATABLOCK
	/* TBD optimize by accumulating and only doing once */
	__atomic_sub_fetch(&ef->encap_db_bytes_enqueued, len, __ATOMIC_SEQ_CST);
#endif

	pos_in_seg_in += len;
	bytes_out_remaining -= len;

	/*
	 * Did we consume seg_in entirely?
	 */
	if (pos_in_seg_in == seg_in_b->current_length) {
	    if (seg_in_b->flags & VLIB_BUFFER_NEXT_PRESENT) {
		/* advance to next segment */
		seg_in_ix = seg_in_b->next_buffer;
		seg_in_b = vlib_get_buffer(vm, seg_in_ix);
		pos_in_seg_in = 0;
	    } else {
		break;
	    }
	} else {
	    /* didn't finish current segment, must be out of room */
	    break;
	}
    }

    /*
     * Values for caller
     */
    *chain_head_index = seg_out_first_ix;
    *chain_tail_index = seg_out_ix;
    *offset_in_new = offset_in_cur;

    return 0;
}

#define ENCAP_N_BLOCK_LENGTHS_MAX 100
typedef struct {
    u32	block_lengths[ENCAP_N_BLOCK_LENGTHS_MAX];
    u32 n_block_lengths;
    u32 buffer_length;
    u16	nsegs;
} etfs3_encap_tx_trace_t;

static u8*
format_encap_tx_trace(u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    etfs3_encap_tx_trace_t *t = va_arg (*args, etfs3_encap_tx_trace_t *);
    u32 indent = format_get_indent (s);
    u32 n_block_lengths;
    u32 *pBl;

    s = format(s, "nsegs %u, nblocks %u\n", t->nsegs, t->n_block_lengths);

    n_block_lengths = t->n_block_lengths;
    pBl = t->block_lengths;
    while (n_block_lengths > 10) {
	s = format(s, "%U%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
	    format_white_space, indent,
	    pBl[0], pBl[1], pBl[2], pBl[3], pBl[4],
	    pBl[5], pBl[6], pBl[7], pBl[8], pBl[9]);
	pBl += 10;
	n_block_lengths -= 10;
    }
    if (n_block_lengths) {
	s = format(s, "%U", format_white_space, indent);
	while (n_block_lengths) {
	    s = format(s, "%u%s", *pBl, ((n_block_lengths > 1)? ",": "\n"));
	    --n_block_lengths;
	    ++pBl;
	}
    }
    return s;
}

/*
 * returns buffer index to put in next frame, or INDEX_INVALID if none.
 * Caller manages frames.
 */
static inline u32
encap_tx_one_inline (
    vlib_main_t			*vm,
    vlib_node_runtime_t		*node,
    struct state_encap_flow	*ef)		/* session encap flow state */
{
    u32	bi_out_head;
    u32	bi_out_tail;
    u32 n_alloc;
    u32	OctetsToSend = ef->etfs_framesize - 4;	/* TBD optimize pre-compute */
#if ! ETFS3_ENABLE_PADDING
    u32 InitialOctetsToSend = OctetsToSend;	/* debug */
#endif
    char *myname = "encap_tx_one";		/* debug */
    u16	nsegs = 1;				/* header */
    u32	block_lengths[ENCAP_N_BLOCK_LENGTHS_MAX];	/* tracing */
    u32 n_block_lengths = 0;

#define ADD_BLOCK_LENGTH(l) \
    do {\
	if (n_block_lengths < (ENCAP_N_BLOCK_LENGTHS_MAX - 1)) {\
	    block_lengths[n_block_lengths++] = l;\
	}\
    } while(0)

    char 		*p_out_head;

    /*
     * Allocate buffer, head of packet
     * TBD: optimization: figure out number of small buffers needed, then
     * allocate in a single operation. Maybe split into multiple nodes.
     */
    n_alloc = etfs3_alloc_buffer_indirect(vm, &bi_out_head);
    if (PREDICT_FALSE(n_alloc != 1)) {
	etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_BLOCKED_ENCODE_TX_OOM,
				       vm->thread_index, ef->index, 1);
	return INDEX_INVALID;
    }
    bi_out_tail = bi_out_head;

    /* header: dst-addr, src-addr, ethertype, offset */
    vlib_buffer_t	*b_out_head = vlib_get_buffer(vm, bi_out_head);

    /*
     * If first buffer in chain does not have this flag set, the
     * dpdk plugin driver transmit code dpdk_validate_rte_mbuf()
     * wipes out the vlib_buffer_t indirect flag for ALL segments
     * in the chain.
     */
    b_out_head->flags |= VLIB_BUFFER_EXT_HDR_VALID;

    p_out_head = vlib_buffer_get_current(b_out_head);
    clib_memcpy((u8 *)p_out_head, &ef->ether_header, sizeof(ef->ether_header));
    u16	*pOffset = (u16 *)((u8 *)p_out_head + sizeof(ef->ether_header));
    *pOffset = 0;	/* default value */

    b_out_head->current_length = sizeof(ef->ether_header) + 2;

    ETFS_DEBUG(190802, 2, "head-of-packet b=%p, OctetsToSend %d\n",
	b_out_head, OctetsToSend);

    int set_offset = 0;

    while (OctetsToSend >= 2) {

	vlib_buffer_t	*b;

	/*
	 * NB: INDEX_INVALID is (u32 ~0), see vnet/dpo/dpo.h.
	 * Not sure if that definition propagates everywhere; do
	 * something if not.
	 */
	if (ef->encap_db_current_index == INDEX_INVALID) {
	    /* No previous partial datablock */

	    u32	n_elts;

	    clib_spinlock_lock(&ef->lock);
	    n_elts = clib_fifo_elts(ef->datablock_fifo);

	    if (n_elts == 0) {
		/* out of datablocks */
		clib_spinlock_unlock(&ef->lock);
		ETFS_DEBUG(190802, 2, "fifo empty\n");
		break;
	    }

	    /* get next datablock from queue */
	    clib_fifo_sub1(ef->datablock_fifo, ef->encap_db_current_index);
	    clib_spinlock_unlock(&ef->lock);

	    ETFS_DEBUG(190802, 1, "fifo had %u\n", n_elts);

	    b = vlib_get_buffer(vm, ef->encap_db_current_index);

	    u16 len = vlib_buffer_length_in_chain(vm, b);

	    ef->encap_db_bytes_remaining = len;
	    ef->encap_db_current_was_fragmented = 0;

#if DEDUCT_QUEUE_BYTES_PER_DATABLOCK
	    __atomic_sub_fetch(&ef->encap_db_bytes_enqueued, len, __ATOMIC_SEQ_CST);
#endif

	} else {
	    b = vlib_get_buffer(vm, ef->encap_db_current_index);
	}

	if (!set_offset) {
	    if (ef->encap_db_current_was_fragmented) {
		*pOffset = clib_host_to_net_u16(ef->encap_db_bytes_remaining);
	    }
	    set_offset = 1;
	}

	ETFS_DEBUG(190802, 1, "have db\n");

	/*
	 * We have some or all of a DataBlock
	 */
	u16	offset_new;
	int	rc;
	u32	new_chain_head_index = INDEX_INVALID;
	u32	new_chain_tail_index;

	rc = tx_add_datablock(
	    vm,
	    ef,
	    OctetsToSend,
	    &new_chain_head_index,
	    &new_chain_tail_index,
	    &offset_new);

	if (rc) {
	    if (new_chain_head_index != INDEX_INVALID)
		etfs3_buffer_free(vm, &new_chain_head_index, 1, "f-tad-f");
	    etfs3_buffer_free(vm, &bi_out_head, 1, "f-tad-f2");
	    if (rc == -ENOMEM) {
		etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_BLOCKED_ENCODE_TX_OOM3,
					       vm->thread_index, ef->index, 1);
	    } else {
		etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_BLOCKED_ENCODE_TX_OTHER,
					       vm->thread_index, ef->index, 1);
	    }

	    ETFS_DEBUG(ENCAP_TX_ONE, 1, "%s: tx_add_datablock failed (3)\n",
		myname);
	    return INDEX_INVALID;
	}

	if (new_chain_head_index != INDEX_INVALID) {
	    vlib_get_buffer(vm, bi_out_tail)->next_buffer =
		new_chain_head_index;
	    vlib_get_buffer(vm, bi_out_tail)->flags |= VLIB_BUFFER_NEXT_PRESENT;
	    bi_out_tail = new_chain_tail_index;
	}

	/*
	 * Update out_head segment count and packet length
	 */
	++nsegs;
	u32 blic = vlib_buffer_index_length_in_chain(vm, new_chain_head_index);
	ASSERT(blic <= OctetsToSend);
	b_out_head->total_length_not_including_first_buffer += blic;

	OctetsToSend -= blic;
	ADD_BLOCK_LENGTH(blic);

	/*
	 * Did we consume entire datablock?
	 */
	if (offset_new >=
	    vlib_buffer_index_length_in_chain(vm, ef->encap_db_current_index)) {

	    /* consumed it all */
	    ETFS_DEBUG(190802, 1, "free consumed rcvd User Frame %p\n",
		vlib_get_buffer(vm, ef->encap_db_current_index));
	    etfs3_buffer_free(vm, &ef->encap_db_current_index, 1, "f-et1cons");
	    ef->encap_db_current_index = INDEX_INVALID;
	    etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_FREED_FROM_QUEUE,
					   vm->thread_index, ef->index, 1);
	    ETFS_DEBUG(ENCAP_TX_ONE, 1, "%s: consumed entire datablock\n",
		myname);
	} else {
	    /* adjust remembered values */
	    ef->encap_db_current_was_fragmented = 1;
	    ef->encap_db_bytes_remaining =
		vlib_buffer_index_length_in_chain(vm,
		    ef->encap_db_current_index) - offset_new;
	    ETFS_DEBUG(ENCAP_TX_ONE, 1, "%s: consumed partial datablock\n",
		myname);
	    etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_FRAGMENT_TX,
					   vm->thread_index, ef->index, 1);
	}

    }

    /*
     * Special case: user has set temporary bypass mode and there
     * is no user frame data to send: don't sent packet that contains
     * only padding. (set_offset should be set IFF there is user frame
     * data present)
     */
    if (!set_offset && ef->etfs_encap_bypass) {
	etfs3_buffer_free(vm, &bi_out_head, 1, "f-et1b");
	ETFS_DEBUG(ENCAP_TX_ONE, 1, "%s: bypass && empty\n", myname);
	return INDEX_INVALID;
    }

#if ETFS3_ENABLE_PADDING
    if (OctetsToSend) {
	u32		bi_pad;
	vlib_buffer_t	*b;

	/*
	 * pad remaining length
	 */

#if ETFS3_PAD_INDIRECT
	/*
	 * Alloc small indirect buffer
	 */
	n_alloc = etfs3_alloc_buffer_indirect(vm, &bi_pad);
	if (PREDICT_FALSE(n_alloc != 1)) {
	    etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_BLOCKED_ENCODE_TX_OOM,
					   vm->thread_index, ef->index, 1);
	    etfs3_buffer_free(vm, &bi_out_head, 1, "f-pad-f");
	    ETFS_DEBUG(ENCAP_TX_ONE, 1, "%s: OOM small indirect\n", myname);
	    return INDEX_INVALID;
	}

	/*
	 * Attach to permanently-allocated padding
	 */
	b = vlib_get_buffer(vm, bi_pad);
	b->flags |= VLIB_BUFFER_EXT_HDR_VALID;

	/*
	 * padding packet is as big as a jumbo packet
	 */
	vlib_buffer_attach(vm, b, vlib_get_buffer(vm, ef->bi_padding_packet));
	b->current_data = vlib_get_buffer(vm, ef->bi_padding_packet)->current_data;
	b->current_length = OctetsToSend;

#else /* ETFS3_PAD_INDIRECT */
	n_alloc = etfs3_alloc_buffer_padding(vm, &bi_pad);
	if (PREDICT_FALSE(n_alloc != 1)) {
	    etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_BLOCKED_ENCODE_TX_OOM,
					   vm->thread_index, ef->index, 1);
	    etfs3_buffer_free(vm, &bi_out_head, 1, "f-pad-f2");
	    return INDEX_INVALID;
	}
	b = vlib_get_buffer(vm, bi_pad);
	b->current_data = 0;
	clib_memset(vlib_buffer_get_current(b), 0, OctetsToSend);
	b->current_length = OctetsToSend;
#endif

	vlib_get_buffer(vm, bi_out_tail)->next_buffer = bi_pad;
	vlib_get_buffer(vm, bi_out_tail)->flags |= VLIB_BUFFER_NEXT_PRESENT;
	vlib_get_buffer(vm, bi_out_head)->total_length_not_including_first_buffer += OctetsToSend;
	bi_out_tail = bi_pad;
	++nsegs;
    }
#else
    /*
     * non-padding case:
     * If there are no user frames in packet, discard entirely
     */
    if (OctetsToSend == InitialOctetsToSend) {
	ETFS_DEBUG(190802, 2, "no user frames, free head %p\n",
	    vlib_get_buffer(vm, bi_out_head));
	etfs3_buffer_free(vm, &bi_out_head, 1, "f-hop-npc");
	return INDEX_INVALID;
    }
#endif /* ETFS3_ENABLE_PADDING */

    /*
     * Now we have a complete packet: send it
     */

     vnet_buffer(b_out_head)->sw_if_index[VLIB_TX] = ef->if_index_tx;
     if (ef->macsec_enabled)
	vnet_buffer(b_out_head)->ipsec.sad_index = ef->ipsec_sa_index;

    /*
     * XXX work around ethernet driver that ignores chained buffers
     * TBD fix me to improve performance
     */
    if (BUFFER_CHAIN_COMPACT(
	vm, ((nsegs > ETFS3_TX_MAX_SEGS) || !(ef->tx_port_is_dpdk)),
	&bi_out_head, ef->tx_mtu)) {
	etfs3_encap_inc_simple_counter(ETFS3_COUNTER_PKT_BLOCKED_ENCODE_TX_OOM2,
				       vm->thread_index, ef->index, 1);
	etfs3_buffer_free(vm, &bi_out_head, 1, "f-comfl");
	return INDEX_INVALID;
    }
    b_out_head = vlib_get_buffer(vm, bi_out_head);


    ETFS_DEBUG_F(190802, 2, "encap_tx_one b_out_head: %U\n  %U\n%c",
	format_vlib_buffer, b_out_head,
	format_buffer_data, b_out_head,
	vlib_buffer_length_in_chain(vm, b_out_head), 0);

    u32	n_trace;
    if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node)))) {
	vlib_trace_buffer(vm, node, ef->next_index, b_out_head, 1 /* follow chain */);
	etfs3_encap_tx_trace_t *tr =
	    vlib_add_trace (vm, node, b_out_head, sizeof (*tr));

	tr->buffer_length = vlib_buffer_length_in_chain(vm, b_out_head);
	tr->nsegs = nsegs;
	tr->n_block_lengths = n_block_lengths;
	clib_memcpy_fast(tr->block_lengths, block_lengths,
	    n_block_lengths * sizeof(block_lengths[0]));

	vlib_set_trace_count (vm, node, n_trace - 1);
    }

    return bi_out_head;
}


decap_rx_runtime_data_t decap_rx_runtime_data_non_macsec = {
    .is_macsec = 0,
};

decap_rx_runtime_data_t decap_rx_runtime_data_macsec = {
    .is_macsec = 1,
};

VLIB_REGISTER_NODE (etfs3_decap_rx_node) = {
  .function = decap_rx_node_fn,
  .name = "etfs3-decap-rx",
  .runtime_data = &decap_rx_runtime_data_non_macsec,
  .runtime_data_bytes = sizeof(decap_rx_runtime_data_non_macsec),
  .vector_size = sizeof (u32),
/*  .format_trace = format_sample_trace, */
  .type = VLIB_NODE_TYPE_INTERNAL,
#if 0
  .n_errors = ETFS3_N_DECAP_ERROR,
  .error_strings = etfs3_decap_error_strings,
#endif
  .n_next_nodes = ETFS3_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
#if 0
        [ETFS3_NEXT_INTERFACE_OUTPUT] = "interface-output",
#endif
#define _(s,n) [ETFS3_NEXT_##s] = n,
    foreach_etfs3_next
#undef _
  },
};

VLIB_REGISTER_NODE (etfs3_decap_rx_node_macsec) = {
  .function = decap_rx_node_fn,
  .name = "etfs3-decap-rx-macsec",
  .runtime_data = &decap_rx_runtime_data_macsec,
  .runtime_data_bytes = sizeof(decap_rx_runtime_data_macsec),
  .vector_size = sizeof (u32),
/*  .format_trace = format_sample_trace, */
  .type = VLIB_NODE_TYPE_INTERNAL,
#if 0
  .n_errors = ETFS3_N_DECAP_ERROR,
  .error_strings = etfs3_decap_error_strings,
#endif
  .n_next_nodes = ETFS3_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
#if 0
        [ETFS3_NEXT_INTERFACE_OUTPUT] = "interface-output",
#endif
#define _(s,n) [ETFS3_NEXT_##s] = n,
    foreach_etfs3_next
#undef _
  },
};


VLIB_REGISTER_NODE (etfs3_encap_rx_node) = {
  .function = encap_rx_node_fn,
  .name = "etfs3-encap-rx",
  .vector_size = sizeof (u32),
  .format_trace = format_encap_rx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
#if 0
  .n_errors = ETFS3_N_ENCAP_ERROR,
  .error_strings = etfs3_encap_error_strings,
#endif
  .n_next_nodes = ETFS3_N_NEXT,

  /* edit / add dispositions here */
  /* This is bogus: these are not used */
  .next_nodes = {
#if 0
        [ETFS3_NEXT_INTERFACE_OUTPUT] = "interface-output",
#endif
#define _(s,n) [ETFS3_NEXT_##s] = n,
    foreach_etfs3_next
#undef _
  },
};

typedef struct {
    uword		*pNpkts;	/* caller's sent-packet counter */
    vlib_node_runtime_t	*node_runtime;
    vlib_main_t		*vm;
} encap_flow_arg_t;

static inline void
encap_tx_flow(
    struct state_encap_flow	*ef,
    void			*arg)
{
    encap_flow_arg_t		*a = (encap_flow_arg_t *)arg;
    u64				now = clib_cpu_time_now ();
    u64				due;	/* cpu time when next tx pkt is due */
    i64				delta;
    i64				count = 1;
    uword			npkts = 0;
    uword			nbytes = 0;

    if (PREDICT_FALSE(!ef->encap_next_desired_tx_cputicks))
	ef->encap_next_desired_tx_cputicks = now;

    due = ef->encap_next_desired_tx_cputicks;
    delta = now - due;

    if (delta < 0) {
	/* too early */
	return;
    }

    /*
     * if the actual time since we were last here is greater than the
     * desired transmission interval, compute how many intervals have
     * elapsed.
     */
    if (delta > (i64)ef->etfs_tx_interval_cputicks) {
	count = (i64) ((delta / ef->etfs_tx_interval_cputicks) + 1);
	/*
	 * Limit to one frame's worth of packets
	 */
	if (count > VLIB_FRAME_SIZE) {
	    count = VLIB_FRAME_SIZE;
	}
	due = now;
    }

    /*
     * Store the time when we should send the next packet
     */
    ef->encap_next_desired_tx_cputicks = due + ef->etfs_tx_interval_cputicks;

    u32		next_index;
    u32		*to_next;
    u32		n_left_to_next;

    next_index = ef->next_index;

    /*
     * Sets to_next to point to u32 that should receive index of packet
     * Sets n_left_to_next to number of slots available
     */
    vlib_get_next_frame(a->vm, a->node_runtime, next_index,
	to_next, n_left_to_next);

    /*
     * Generate packet(s)
     */
    while (count--) {
	u32 bi;
	vlib_buffer_t *buf;

    	bi = encap_tx_one_inline(a->vm, a->node_runtime, ef);
	if (bi != INDEX_INVALID) {
	    ++npkts;

	    *to_next = bi;
	    ++to_next;
	    n_left_to_next -= 1;

	    buf = vlib_get_buffer(etfs3_main.vlib_main, bi);
	    ASSERT(buf);
	    nbytes += vlib_buffer_length_in_chain(etfs3_main.vlib_main, buf);

#if 0
	    vlib_trace_buffer(a->vm, a->node_runtime, next_index, buf, 1 /* follow chain */);
#endif
	    if (!n_left_to_next) {
		vlib_put_next_frame(a->vm, a->node_runtime,
		    next_index, n_left_to_next);
		vlib_get_next_frame(a->vm, a->node_runtime,
		    next_index, to_next, n_left_to_next);
	    }
	}
    }
    vlib_put_next_frame(a->vm, a->node_runtime, next_index, n_left_to_next);
    *(a->pNpkts) += npkts;

    etfs3_encap_inc_combined_counter(ETFS3_COUNTER_TX,
				     etfs3_main.vlib_main->thread_index,
				     ef->index, npkts, nbytes);
}

VLIB_NODE_FN(etfs3_encap_tx_poll_node)
(vlib_main_t *vm, vlib_node_runtime_t *node_runtime, vlib_frame_t * __clib_unused frame)
{
    uword		npkts = 0;
    encap_flow_arg_t	a;

    a.pNpkts = &npkts;
    a.node_runtime = node_runtime;
    a.vm = vm;

    struct encap_tx_thread	*tx_thr;
    struct state_encap_flow	**ef;

    tx_thr = vec_elt_at_index(etfs3_main.encap_tx_threads,
	vlib_get_thread_index());

    clib_spinlock_lock(&tx_thr->flow_lock);
    vec_foreach(ef, tx_thr->flows) {
	encap_tx_flow(*ef, &a);
    }
    clib_spinlock_unlock(&tx_thr->flow_lock);

    return npkts;
}

VLIB_REGISTER_NODE(etfs3_encap_tx_poll_node) = {
    .name = "etfs3-output",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_DISABLED,
    .format_trace = format_encap_tx_trace,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

    .n_next_nodes = ETFS3_N_NEXT,
    .next_nodes = {
#define _(s,n) [ETFS3_NEXT_##s] = n,
    foreach_etfs3_next
#undef _
    },
};


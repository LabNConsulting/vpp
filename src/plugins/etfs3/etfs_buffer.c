/*
 * Copyright (c) 2020, LabN Consulting, L.L.C
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

#include "etfs_buffer.h"

u8 *
b_indirect_data(vlib_buffer_t *b)
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

int
b_cursor_set(
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

int
b_cursor_advance(
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
 * Returns 0 for success, otherwise malformed packet
 */
int
b_get_u32(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u32					*val32bit)
{
    u8					*p[4];

    datablock_reassembly_cursor_t	c = *curs;

    /* we operate on our own copy of cursor, leave caller's cursor alone */

    p[0] = c.seg->data + c.seg->current_data + c.offset_in_seg;
    if (b_cursor_advance(vm, &c, 1))
	return -1;
    p[1] = c.seg->data + c.seg->current_data + c.offset_in_seg;
    if (b_cursor_advance(vm, &c, 1))
	return -1;
    p[2] = c.seg->data + c.seg->current_data + c.offset_in_seg;
    if (b_cursor_advance(vm, &c, 1))
	return -1;
    p[3] = c.seg->data + c.seg->current_data + c.offset_in_seg;

    /* network to host byte-order conversion happens here */
    *val32bit = (*p[0] << 24) | (*p[1] << 16) | (*p[2] << 8) | *p[3];

    return 0;
}


/*
 * Returns 0 for success, otherwise malformed packet
 */
int
b_get_u16(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					*val16bit)
{
    u8					*pMSB;
    u8					*pLSB;
    datablock_reassembly_cursor_t	c = *curs;

    /* we operate on our own copy of cursor, leave caller's cursor alone */

    pMSB = c.seg->data + c.seg->current_data + c.offset_in_seg;
    if (b_cursor_advance(vm, &c, 1))
	return -1;
    pLSB = c.seg->data + c.seg->current_data + c.offset_in_seg;

    /* network to host byte-order conversion happens here */
    *val16bit = *pMSB << 8 | *pLSB;

    return 0;
}

int
b_get_u8(
    datablock_reassembly_cursor_t	*curs,
    u8					*val8bit)
{
    u8					*pMSB;

    /* leave caller's cursor alone */

    pMSB = curs->seg->data + curs->seg->current_data + curs->offset_in_seg;

    /* network to host byte-order conversion happens here */
    *val8bit = *pMSB;

    return 0;
}

u32
b_bytes_available(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*scurs)
{
    i64		avail;

    avail = vlib_buffer_length_in_chain(vm, scurs->pkt) -
	scurs->offset_current_seg - 
	scurs->offset_in_seg;

    if ((avail & 0xffffffff) == avail)
	return (avail & 0xffffffff);
    return 0;
}

/*
 * copy out N bytes to caller's data area
 */
int
b_get_bytes(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*_scurs,	/* src */
    char				*_dst,
    u16					copylength)
{
    datablock_reassembly_cursor_t	scurs;
    char				*dst;
    u16					octets_to_copy;

    /* fail if not enough data in source */
    if ((vlib_buffer_length_in_chain(vm, _scurs->pkt) -
	_scurs->offset_current_seg - 
	_scurs->offset_in_seg) < copylength) {

	return 0;
    }

    scurs = *_scurs;
    dst = _dst;
    octets_to_copy = copylength;

    while (scurs.seg && octets_to_copy) {

	i32	avail_this_segment;
	u16	copylen;

	avail_this_segment = scurs.seg->current_length - scurs.offset_in_seg;
	ASSERT(avail_this_segment == (avail_this_segment & 0xffff));
	copylen = clib_min(octets_to_copy, (u16)avail_this_segment);
	ASSERT(copylen);

	clib_memcpy_fast(
	    dst,
	    scurs.seg->data + scurs.seg->current_data + scurs.offset_in_seg,
	    copylen);

	b_cursor_advance(vm, &scurs, copylen);
	dst += copylen;

	octets_to_copy -= copylen;
    }

    ASSERT(octets_to_copy == 0);

    return copylength;
}

/*
 * copy subset of source buffer and append to destination buffer
 *
 * Does not handle indirect either in src or dst yet
 */
u16
b_copy_append(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*_scurs,	/* src */
    vlib_buffer_t			*dst,
    u16					copylength,
    bool				with_alloc, /* allow dst append buf */
    const char				*tag)
{
    datablock_reassembly_cursor_t	scurs;
    u16					octets_to_copy;
    u16					count;
    vlib_buffer_t			*dst_last;
#if ETFS_ENABLE_BUFFER_NOTES
    vlib_buffer_t			*last_dst_last;
#endif

    /* fail if not enough data in source */
    if ((vlib_buffer_length_in_chain(vm, _scurs->pkt) -
	_scurs->offset_current_seg - 
	_scurs->offset_in_seg) < copylength) {

	return 0;
    }

    scurs = *_scurs;
    octets_to_copy = copylength;

    /* find last buffer in destination chain */
    vlib_buffer_t	*p;
    for (dst_last = dst; (p = vlib_get_next_buffer(vm, dst_last)); dst_last = p);

#if ETFS_ENABLE_BUFFER_NOTES
    last_dst_last = dst_last;
#endif

    while (scurs.seg && octets_to_copy) {

	i32	avail_this_segment;
	u16	copylen;

	avail_this_segment = scurs.seg->current_length - scurs.offset_in_seg;
	ASSERT(avail_this_segment == (avail_this_segment & 0xffff));
	copylen = clib_min(octets_to_copy, (u16)avail_this_segment);
	ASSERT(copylen);

	if (with_alloc) {
	    count = vlib_buffer_chain_append_data_with_alloc(vm, dst, &dst_last,
		scurs.seg->data + scurs.seg->current_data + scurs.offset_in_seg,
		copylen);
	} else {
	    count = vlib_buffer_chain_append_data(vm, dst, dst_last,
		scurs.seg->data + scurs.seg->current_data + scurs.offset_in_seg,
		copylen);
	}

	b_cursor_advance(vm, &scurs, count);
	octets_to_copy -= count;

	if (count != copylen) {
	    /* couldn't allocate */
	    break;
	}
    }

#if ETFS_ENABLE_BUFFER_NOTES
    while (last_dst_last != dst_last) {
	last_dst_last = vlib_get_next_buffer(vm, last_dst_last);
	if (last_dst_last)
	    vlib_buffer_note_add(last_dst_last, "+%s:%s", __func__, tag);
    }
#endif

    *_scurs = scurs;

    return copylength - octets_to_copy;
}


/*
 * Make an indirect mbuf chain referencing the User Frame starting
 * at the cursor and extending for DataBlockLength octets.
 *
 * Does NOT adjust cursor.
 *
 * Returns pointer to user frame or NULL if no memory
 */
vlib_buffer_t *
/* getUserFrameAtCursor( */
b_clone_partial(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					DataBlockLength,
    vlib_buffer_t			**seg_last,
    u32					*uf_ix_returned,
    bool				allow_indirect)
{
    u32					uf_ix = ~0u;
    vlib_buffer_t			*uf = NULL;

    vlib_buffer_t			*seg_src;
    vlib_buffer_t			*seg_dst;
    vlib_buffer_t			*seg_dst_prev = NULL;
    bool				do_copy = false;

    /*
     * Cursor should be pointing to start of (src) UF data.
     */
    u16	octets_to_copy = DataBlockLength;

    if (seg_last && *seg_last)
	seg_dst_prev = *seg_last;

#define ETFS_BUFFER_COPY_LE	128

    if (!allow_indirect || (octets_to_copy < ETFS_BUFFER_COPY_LE))
	do_copy = true;

    /*
     * short frames: copy instead of indirect
     */
    if (do_copy) {
	u32	n_alloc;
	u32	seg_dst_ix;

	/*
	 * Assumption: we can fit octets_to_copy bytes in one buffer
	 */
	n_alloc = b_alloc_bi(vm, &seg_dst_ix, __func__);
	if (n_alloc != 1)
	    return NULL;

	seg_dst = vlib_get_buffer(vm, seg_dst_ix);
	seg_dst->flags |= VLIB_BUFFER_EXT_HDR_VALID;

	ASSERT(vlib_buffer_can_put(vm, seg_dst, octets_to_copy));

	for (seg_src = curs->seg;
	    seg_src && octets_to_copy;
	    seg_src = vlib_get_next_buffer(vm, seg_src)) {

	    u16 copylen;
	    u16 offset_in_seg_src;

	    /* offset_in_seg matters for first source buffer in chain */
	    if (seg_src == curs->seg) {
		offset_in_seg_src = curs->offset_in_seg;
	    } else {
		offset_in_seg_src = 0;
	    }
	    /* NB already checked before loop that dst was big enough */
	    copylen = clib_min(octets_to_copy,
		seg_src->current_length - offset_in_seg_src);

            clib_memcpy_fast(vlib_buffer_put_uninit(seg_dst, copylen),
		vlib_buffer_get_current(seg_src) + offset_in_seg_src,
		copylen);

	    octets_to_copy -= copylen;
	}

	if (!uf) {
	    uf = seg_dst;
	    uf_ix = seg_dst_ix;
	}

	if (seg_dst_prev) {
	    seg_dst_prev->next_buffer = seg_dst_ix;
	    seg_dst_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	}

	seg_dst_prev = seg_dst;

	goto done;
    }

    for (seg_src = curs->seg;
	seg_src && octets_to_copy;
	seg_src = vlib_get_next_buffer(vm, seg_src)) {

	u32	n_alloc;
	u32	seg_dst_ix;

	n_alloc = b_alloc_bi(vm, &seg_dst_ix, __func__);

	if (n_alloc != 1) {
	    b_free_chain(vm, uf, __func__);
	    return NULL;
	}

	seg_dst = vlib_get_buffer(vm, seg_dst_ix);
	seg_dst->flags |= VLIB_BUFFER_EXT_HDR_VALID;
	vlib_buffer_attach(vm, seg_dst, seg_src);

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

	octets_to_copy -= seg_dst->current_length;

	if (!uf) {
	    uf = seg_dst;
	    uf_ix = seg_dst_ix;
	}

	if (seg_dst_prev) {
	    seg_dst_prev->next_buffer = seg_dst_ix;
	    seg_dst_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	}

	seg_dst_prev = seg_dst;
    }
done:

    if (seg_last)
	*seg_last = seg_dst_prev;
    if (uf_ix_returned)
	*uf_ix_returned = uf_ix;
    return uf;
}

/*
 * b_chain_compact() takes a multi-segment buffer chain representing
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
int
b_chain_compact(vlib_main_t *vm, u32 *bi_chain, u32 mtu)
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

    /* ethernet header is 14 bytes */
    ASSERT (data_length <= (mtu + 14));

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
	    u32 n_alloc = b_alloc_bi(vm, &bi_dst, __func__);
	    if (PREDICT_FALSE(n_alloc != 1)) {
		b_free_chain(vm, b_dst_first, __func__);
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
	    b_indirect_data(b_src) + b_src->current_data +
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

    /* free */
    b_free_bi_chain(vm, bi_chain, 1, "f-comp");

    *bi_chain = bi_new;
    return 0;
}

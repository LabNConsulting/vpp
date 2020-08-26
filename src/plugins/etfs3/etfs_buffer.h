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
#ifndef __included_etfs_buffer_h__
#define __included_etfs_buffer_h__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <vlib/vlib.h>

#if ETFS_TX_MULTISEG_INDIRECT
#define B_CHAIN_COMPACT(vm, need_compact, pBI, mtu) \
    ((need_compact)? b_chain_compact((vm),(pBI), (mtu)): 0)
#else
#define B_CHAIN_COMPACT(vm, need_compact, pBI, mtu) \
    b_chain_compact((vm),(pBI), (mtu))
#endif

typedef struct {
    vlib_buffer_t			*pkt;	/* current pkt */
    vlib_buffer_t			*seg;	/* current segment */
    u16					offset_current_seg;
    u16					offset_in_seg;
} datablock_reassembly_cursor_t;

static inline u16
b_offset_of(
    datablock_reassembly_cursor_t	*curs)
{
    return (curs->offset_current_seg + curs->offset_in_seg);
}

static inline int
b_alloc_bi(vlib_main_t *vm, u32 *bi_new, const char *tag)
{
    vlib_buffer_t	*b;

    u32 n = vlib_buffer_alloc(vm, bi_new, 1);
    if (!n)
	return 0;

    ASSERT(n == 1);

    b = vlib_get_buffer(vm, *bi_new);

    ASSERT(!(b->flags & VLIB_BUFFER_INDIRECT));

    b->flags = 0;

#if ETFS_ENABLE_BUFFER_NOTES
    vlib_buffer_note_add(b, "+%s", tag);
#endif

    return n;
}

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
/* follows and frees each chain */
static inline void
b_free_bi_chain(
    vlib_main_t	*vm,
    u32		*buffers,
    u32		n_buffers,
    const char	*tag)
{
    /*
     * TBD can we make more efficient by pushing array handling to lower level?
     */
    while (n_buffers--) {

	vlib_buffer_t	*b;

	b = vlib_get_buffer(vm, *buffers);

	ASSERT(b->ref_count > 0);
#if ETFS_ENABLE_BUFFER_NOTES
	vlib_buffer_note_add(b, "-%s", tag);
#endif
	vlib_buffer_dpdk_free(vm, b);
	buffers++;
    }
}

/* deprecated */
#define etfs_buffer_free(v,b,n,t) b_free_bi_chain(v,b,n,t)

static inline void
b_free_chain(vlib_main_t *vm, vlib_buffer_t *b, const char *tag)
{
    if (!b)
	return;

    u32 b_ix = vlib_get_buffer_index(vm, b);
    b_free_bi_chain(vm, &b_ix, 1, tag);
}

/* deprecated */
#define free_vlib_buffer_chain(v,b) b_free_v(v,b,__func__);

extern u8 *
b_indirect_data(vlib_buffer_t *b);

extern int
b_cursor_set(
    vlib_main_t				*vm,
    vlib_buffer_t			*pkt,
    datablock_reassembly_cursor_t	*curs,
    u16					offset);


extern int
b_cursor_advance(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					increment);

extern int
b_get_u32(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u32					*val32bit);

extern int
b_get_u16(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					*val16bit);

extern int
b_get_u8(
    datablock_reassembly_cursor_t	*curs,
    u8					*val8bit);

extern u32
b_bytes_available(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*scurs);

extern int
b_get_bytes(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*_scurs,	/* src */
    char				*_dst,
    u16					copylength);

u16
b_copy_append(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*_scurs,	/* src */
    vlib_buffer_t			*dst,
    u16					copylength,
    bool				with_alloc,
    const char				*tag);

extern vlib_buffer_t *
b_clone_partial(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*curs,
    u16					DataBlockLength,
    vlib_buffer_t			**seg_last,
    u32					*uf_ix_returned,
    bool				allow_indirect);

extern int
b_chain_compact(vlib_main_t *vm, u32 *bi_chain, u32 mtu);

#ifdef __cplusplus
}
#endif

#endif /* __included_etfs_buffer_h__ */

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef include_dpdk_buffer_h
#define include_dpdk_buffer_h

#undef always_inline
#define ALLOW_EXPERIMENTAL_API

#define DEBUG_BUFFER_NOTES 0
#if DEBUG_BUFFER_NOTES
#include <vppinfra/bihash_8_8.h>
/*
 * per-buffer note
 */
struct dpdk_buffer_debug_main
{
  BVT (clib_bihash) note_table;	/* indexed by mb, ptr to note */
};

extern struct dpdk_buffer_debug_main bdm;
#endif

#include <rte_config.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#include <vnet/vnet.h>
#include <vlib/vlib.h>

#define rte_mbuf_from_vlib_buffer(x) (((struct rte_mbuf *)x) - 1)
#define vlib_buffer_from_rte_mbuf(x) ((vlib_buffer_t *)(x+1))

extern struct rte_mempool **dpdk_mempool_by_buffer_pool_index;
extern struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index;

always_inline vlib_buffer_t *
dpdk_validate_rte_mbuf (vlib_main_t * vm, vlib_buffer_t * b,
			int maybe_multiseg)
{
  struct rte_mbuf *mb, *first_mb, *last_mb;
  last_mb = first_mb = mb = rte_mbuf_from_vlib_buffer (b);

  /* buffer is coming from non-dpdk source so we need to init
     rte_mbuf header */
  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0))
    {
#if 0
      /* XXX Since we don't set the valid flag this gets called multiple times */
      clib_warning
	("%s: buffer ext header not valid for buffer 0x%x reseting",
	 __FUNCTION__, vlib_get_buffer_index (vm, b));
#endif
      ASSERT ((b->flags & VLIB_BUFFER_INDIRECT) == 0);
      ASSERT ((mb->ol_flags & IND_ATTACHED_MBUF) == 0);
      rte_pktmbuf_reset (mb);
      b->flags |= VLIB_BUFFER_EXT_HDR_VALID;
    }

  first_mb->nb_segs = 1;
  mb->data_len = b->current_length;
  /* XXX chopps: why would we use the function here and not calculate ourselves */
  mb->pkt_len = maybe_multiseg ? vlib_buffer_length_in_chain (vm, b) :
    b->current_length;
  mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
  u16 pktlen = b->current_length;

  while (maybe_multiseg && (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      mb = rte_mbuf_from_vlib_buffer (b);
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0))
	{
#if 0
	  /* XXX Since we don't set the valid flag this gets called multiple times
	   */
	  clib_warning
	    ("%s: buffer ext header not valid for buffer in chain 0x%x reseting",
	     __FUNCTION__, vlib_get_buffer_index (vm, b));
#endif
	  ASSERT ((b->flags & VLIB_BUFFER_INDIRECT) == 0);
	  ASSERT ((mb->ol_flags & IND_ATTACHED_MBUF) == 0);
	  rte_pktmbuf_reset (mb);
	  b->flags |= VLIB_BUFFER_EXT_HDR_VALID;
	}
      last_mb->next = mb;
      last_mb = mb;
      mb->data_len = b->current_length;
      mb->pkt_len = b->current_length;
      pktlen += b->current_length;
      mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
      first_mb->nb_segs++;
      if (PREDICT_FALSE (b->ref_count > 1))
	mb->pool =
	  dpdk_no_cache_mempool_by_buffer_pool_index[b->buffer_pool_index];
    }
  last_mb->next = NULL;
  ASSERT (first_mb->pkt_len == pktlen);
  return b;
}

clib_error_t *dpdk_buffer_pools_create (vlib_main_t * vm);

#endif /* include_dpdk_buffer_h */

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

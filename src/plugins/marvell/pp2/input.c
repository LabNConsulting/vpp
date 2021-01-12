/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <marvell/pp2/pp2.h>

#define foreach_mrvl_pp2_input_error \
  _(PPIO_RECV, "pp2_ppio_recv error") \
  _(BPOOL_GET_NUM_BUFFS, "pp2_bpool_get_num_buffs error") \
  _(BPOOL_PUT_BUFFS, "pp2_bpool_put_buffs error") \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(MAC_CE, "MAC error (CRC error)") \
  _(MAC_OR, "overrun error") \
  _(MAC_RSVD, "unknown MAC error") \
  _(MAC_RE, "resource error") \
  _(IP_HDR, "ip4 header error")

typedef enum
{
#define _(f,s) MRVL_PP2_INPUT_ERROR_##f,
  foreach_mrvl_pp2_input_error
#undef _
    MRVL_PP2_INPUT_N_ERROR,
} mrvl_pp2_input_error_t;

static __clib_unused char *mrvl_pp2_input_error_strings[] = {
#define _(n,s) s,
  foreach_mrvl_pp2_input_error
#undef _
};

static_always_inline void
mrvl_pp2_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node, u32 next0,
		      vlib_buffer_t * b0, uword * n_trace,
		      mrvl_pp2_if_t * ppif, struct pp2_ppio_desc *d)
{
  mrvl_pp2_input_trace_t *tr;
  vlib_trace_buffer (vm, node, next0, b0,
		     /* follow_chain */ 0);
  vlib_set_trace_count (vm, node, --(*n_trace));
  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
  tr->next_index = next0;
  tr->hw_if_index = ppif->hw_if_index;
  clib_memcpy_fast (&tr->desc, d, sizeof (struct pp2_ppio_desc));
}

static_always_inline u16
mrvl_pp2_set_buf_data_len_flags (vlib_buffer_t * b, struct pp2_ppio_desc *d,
				 u32 add_flags)
{
  u16 len;
  len = pp2_ppio_inq_desc_get_pkt_len (d);
  b->total_length_not_including_first_buffer = 0;
  b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID | add_flags;

  if (add_flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    vnet_buffer (b)->l2_hdr_offset = MV_MH_SIZE;	// == 2


  if (add_flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    {
      u16 offset = DM_RXD_GET_L3_OFF (d);
      vnet_buffer (b)->l3_hdr_offset = offset;
      b->current_data = offset;
      b->current_length = len - offset + MV_MH_SIZE;
    }
  else
    {
      b->current_data = MV_MH_SIZE;
      b->current_length = len;
    }

  if (add_flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    vnet_buffer (b)->l4_hdr_offset = vnet_buffer (b)->l3_hdr_offset +
      DM_RXD_GET_IPHDR_LEN (d) * 4;

  return len;
}

static_always_inline u16
mrvl_pp2_next_from_desc (vlib_node_runtime_t * node, struct pp2_ppio_desc * d,
			 vlib_buffer_t * b, u32 * next)
{
  u8 l3_info;
  /* ES bit set means MAC error  - drop and count */
  if (PREDICT_FALSE (DM_RXD_GET_ES (d)))
    {
      *next = VNET_DEVICE_INPUT_NEXT_DROP;
      u8 ec = DM_RXD_GET_EC (d);
      if (ec == 0)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_CE];
      else if (ec == 1)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_OR];
      else if (ec == 2)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_RSVD];
      else if (ec == 3)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_RE];
      return mrvl_pp2_set_buf_data_len_flags (b, d, 0);
    }

  l3_info = DM_RXD_GET_L3_PRS_INFO (d);
  switch (l3_info)
    {
    case 1:
    case 2:
    case 3:
      /* ipv4 packet can be value 1, 2 or 3 */
      if (PREDICT_FALSE (DM_RXD_GET_L3_IP4_HDR_ERR (d) != 0))
	{
	  *next = VNET_DEVICE_INPUT_NEXT_DROP;
	  b->error = node->errors[MRVL_PP2_INPUT_ERROR_IP_HDR];
	  return mrvl_pp2_set_buf_data_len_flags (b, d, 0);
	}
      *next = VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT;
      return mrvl_pp2_set_buf_data_len_flags
	(b, d,
	 VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L4_HDR_OFFSET_VALID | VNET_BUFFER_F_IS_IP4);
    case 4:
    case 5:
      /* ipv6 packet can be value 4 or 5 */
      *next = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
      return mrvl_pp2_set_buf_data_len_flags
	(b, d,
	 VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L4_HDR_OFFSET_VALID | VNET_BUFFER_F_IS_IP6);
    case 0:
      /* "N/A" (?) */
    case 6:
      /* ARP */
    case 7:
      /* User defined */
    default:
      *next = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      return mrvl_pp2_set_buf_data_len_flags (b, d,
					      VNET_BUFFER_F_L2_HDR_OFFSET_VALID);
    }
}

static_always_inline u32
mrvl_pp2_bpool_get_num_buffs (struct pp2_bpool *pool)
{
  u32 n_bufs;
  int err = pp2_bpool_get_num_buffs(pool, &n_bufs);
  ASSERT(PREDICT_TRUE(!err));
  return n_bufs;
}

#ifdef MRVL_PP2_PKT_DEBUG
static_always_inline int
log_bppe (const char *prefix, u32 pp2_id, u32 port_id,
	  struct pp2_bpool *bpool, int last_bppe)
{
  uintptr_t cpu_slot = GET_HW_BASE (bpool)[PP2_DEFAULT_REGSPACE].va;
  int bppe = pp2_reg_read (cpu_slot,
			   MVPP2_BM_POOL_PTRS_NUM_REG (bpool->id))
    & MVPP22_BM_POOL_PTRS_NUM_MASK;
  u32 bppi = pp2_reg_read (cpu_slot,
			   MVPP2_BM_BPPI_PTRS_NUM_REG (bpool->id))
    & MVPP2_BM_BPPI_PTR_NUM_MASK;

  (void)bppi;
  if (last_bppe != bppe)
    mrvl_pp2_pkt_debug
      ("%s: %s: ppio[%u]:%u num_buffs update bppe %u (%+d) bppi %u total: %u",
       __FUNCTION__, prefix, pp2_id, port_id, bppe, bppe - last_bppe, bppi,
       bppe + bppi);
  return bppe;
}
#endif

static inline uword
mrvl_pp2_process_rx_burst (vlib_main_t * vm, vlib_node_runtime_t * node,
                           mrvl_pp2_if_t * ppif, mrvl_pp2_per_thread_data_t *ptd,
                           u32 n_left)
{
  vlib_buffer_t bt;
  vlib_buffer_t **b = ptd->bp;
  u32 *bi = ptd->bi;
  struct pp2_ppio_desc *d = ptd->descs;
  uword n_rx_bytes = 0;
  u32 next0, next1;
  u32 next2, next3;
  u32 if_next_index = ppif->per_interface_next_index;
  int has_features = vnet_device_input_have_features (ppif->sw_if_index);

  uword n_trace = vlib_get_trace_count (vm, node);


  /* Assert the fact that we only have one NUMA node */
  ASSERT(vlib_buffer_pool_get_default_for_numa (vm, vm->numa_node) ==
         ppif->inqs[0].buffer_pool_index);

  /* copy template into local variable - will save per packet load */
  vlib_buffer_copy_template (&bt, &ptd->buffer_template);
  vnet_buffer (&bt)->sw_if_index[VLIB_RX] = ppif->sw_if_index;
  bt.buffer_pool_index = ppif->inqs[0].buffer_pool_index;

  vlib_get_buffers (vm, bi, b, n_left);

  u32 *to[VNET_DEVICE_INPUT_N_NEXT_NODES] = {};
  u32 *eto[VNET_DEVICE_INPUT_N_NEXT_NODES] = {};

  while (n_left >= 4)
    {
      if (n_left >= 10)
	{
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	}

      vlib_buffer_copy_template (b[0], &bt);
      vlib_buffer_copy_template (b[1], &bt);
      vlib_buffer_copy_template (b[2], &bt);
      vlib_buffer_copy_template (b[3], &bt);

      if (PREDICT_TRUE(if_next_index == ~0))
        {
          n_rx_bytes += mrvl_pp2_next_from_desc (node, &d[0], b[0], &next0);
          n_rx_bytes += mrvl_pp2_next_from_desc (node, &d[1], b[1], &next1);
          n_rx_bytes += mrvl_pp2_next_from_desc (node, &d[2], b[2], &next2);
          n_rx_bytes += mrvl_pp2_next_from_desc (node, &d[3], b[3], &next3);
          if (has_features)
            vnet_feature_start_device_input_x4 (ppif->sw_if_index,
                                                &next0, &next1, &next2, &next3,
                                                b[0], b[1], b[2], b[3]);
        }
      else
        {
          /*
           * Should move this into it's own function which doesn't use array of
           * 'to'
           */
          n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b[0], &d[0], 0);
          n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b[1], &d[1], 0);
          n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b[2], &d[2], 0);
          n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b[3], &d[3], 0);
          next0 = next1 = if_next_index;
          next2 = next3 = if_next_index;
        }

      vlib_put_get_next_frame_a(vm, node, next0, to, eto);
      vlib_put_get_next_frame_a(vm, node, next1, to, eto);
      vlib_put_get_next_frame_a(vm, node, next2, to, eto);
      vlib_put_get_next_frame_a(vm, node, next3, to, eto);

      *to[next0]++ = bi[0];
      *to[next1]++ = bi[1];
      *to[next2]++ = bi[2];
      *to[next3]++ = bi[3];

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      if (PREDICT_FALSE(n_trace))
        mrvl_pp2_input_trace (vm, node, next0, b[0], &n_trace, ppif, &d[0]);
      if (PREDICT_FALSE(n_trace))
        mrvl_pp2_input_trace (vm, node, next1, b[1], &n_trace, ppif, &d[1]);
      if (PREDICT_FALSE(n_trace))
        mrvl_pp2_input_trace (vm, node, next2, b[2], &n_trace, ppif, &d[2]);
      if (PREDICT_FALSE(n_trace))
        mrvl_pp2_input_trace (vm, node, next3, b[3], &n_trace, ppif, &d[3]);

      /* next */
      d += 4;
      b += 4;
      bi += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      vlib_buffer_copy_template (b[0], &bt);

      if (PREDICT_TRUE(if_next_index == ~0))
        {
          n_rx_bytes += mrvl_pp2_next_from_desc (node, &d[0], b[0], &next0);
          if (has_features)
            vnet_feature_start_device_input_x1 (ppif->sw_if_index, &next0, b[0]);
        }
      else
        {
          n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b[0], &d[0], 0);
          next0 = if_next_index;
        }
      vlib_put_get_next_frame_a(vm, node, next0, to, eto);
      *to[next0]++ = bi[0];
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      if (PREDICT_FALSE (n_trace))
        mrvl_pp2_input_trace (vm, node, next0, b[0], &n_trace, ppif, &d[0]);

      /* next */
      d += 1;
      b += 1;
      bi += 1;
      n_left -= 1;
    }

  /* Put all the packets that haven't been yet */
  for (uint i = 0; i < VNET_DEVICE_INPUT_N_NEXT_NODES; i++)
    vlib_put_next_frame (vm, node, i, to[i], eto[i]);

  return n_rx_bytes;

}

static_always_inline uword
mrvl_pp2_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame, mrvl_pp2_if_t * ppif,
			      u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  u32 thread_index = vm->thread_index;
  mrvl_pp2_inq_t *inq = vec_elt_at_index (ppif->inqs, qid);
  mrvl_pp2_per_thread_data_t *ptd =
    vec_elt_at_index (ppm->per_thread_data, thread_index);
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  /* NOTE: fetching < full FRAME allows larger downstream computations w/o drops. */
  u16 batch_size, n_desc = VLIB_FRAME_SIZE / 2;
  u32 n_bufs;

#ifdef MRVL_PP2_PKT_DEBUG
  (void) log_bppe ("PRE: ", ppif->ppio->pp2_id, ppif->ppio->port_id,
		   inq->bpool, ptd->last_bppe);
#endif

  vec_validate_aligned (ptd->descs, n_desc, CLIB_CACHE_LINE_BYTES);
  if (PREDICT_FALSE (pp2_ppio_recv (ppif->ppio, 0, qid, ptd->descs, &n_desc)))
    {
      vlib_error_count (vm, node->node_index, MRVL_PP2_INPUT_ERROR_PPIO_RECV,
			1);
      n_desc = 0;
    }
  n_rx_packets = n_desc;

  /*
   * Extract the buffer index, we don't actually need the high byte of the cookie!
   *
   * Prefetch code was tested here, and it under-performed a simple loop.
   */
  for (int i = 0; i < n_desc; i++)
    ptd->bi[i] = ptd->descs[i].cmds[6];

  if (n_desc)
    {
      mrvl_pp2_pkt_debug
	("%s: sw_if_index %u ppio[%u]:%u n_desc %u of %u", __FUNCTION__,
	 ppif->sw_if_index, ppif->ppio->pp2_id, ppif->ppio->port_id, n_desc,
	 VLIB_FRAME_SIZE);
    }

  n_rx_bytes += mrvl_pp2_process_rx_burst (vm, node, ppif, ptd, n_rx_packets);

  vlib_increment_combined_counter
    (vnm->interface_main.combined_sw_if_counters +
     VNET_INTERFACE_COUNTER_RX, thread_index,
     ppif->hw_if_index, n_rx_packets, n_rx_bytes);

  n_bufs = mrvl_pp2_bpool_get_num_buffs (inq->bpool);

#ifdef MRVL_PP2_PKT_DEBUG
  ptd->last_bppe =
    log_bppe ("POST: ", ppif->ppio->pp2_id, ppif->ppio->port_id, inq->bpool,
	      ptd->last_bppe);
#endif
  /*
   * Refill the PPIO buffer manager pool. Be careful as sometimes it has more
   * than required.
   */
  if (n_bufs > inq->size)
    n_bufs = 0;
  else
    n_bufs = inq->size - n_bufs;

#define ALIGN_PP2(x, a) (((x) + ((a) - 1)) & (~((a) - 1)))
  /* Don't bother requesting an unalligned amount of buffers */
  n_bufs = ALIGN_PP2 (n_bufs, 8);
  batch_size = VLIB_FRAME_SIZE;
  while (n_bufs >= VLIB_FRAME_SIZE)
    {
      u16 n_alloc, i;
      struct buff_release_entry *e = ptd->bre;
      u32 *bi = ptd->bi;
      u16 alloc_size;

      alloc_size = clib_min (n_bufs, batch_size);
      // XXX should align to what the chip is actually limited to, might be 8 or 16.
      alloc_size = ALIGN_PP2 (alloc_size, 8);

      mrvl_pp2_pkt_debug
	("%s: sw_if_index %u fill buffers ppio[%u]:%u n_bufs %u (allocsz %u batchsz %u inqsz %u)",
	 __FUNCTION__, ppif->sw_if_index, ppif->ppio->pp2_id,
	 ppif->ppio->port_id, n_bufs, alloc_size, batch_size, inq->size);

      n_alloc = vlib_buffer_alloc (vm, ptd->bi, alloc_size);
      i = n_alloc;

      /* We can only add groups of 8 buffers */
      alloc_size = n_alloc;
      n_alloc = ALIGN_PP2 (n_alloc, 8);

      if (alloc_size != n_alloc)
	{
	  mrvl_pp2_pkt_debug
	    ("%s: sw_if_index %u Odd number of fill buffers ppio[%u]:%u num buffers %u dropping %u",
	     __FUNCTION__, ppif->sw_if_index, ppif->ppio->pp2_id,
	     ppif->ppio->port_id, alloc_size, alloc_size - n_alloc);
	  vlib_buffer_free (vm, bi, alloc_size - n_alloc);
	  bi += alloc_size - n_alloc;
	}

      if (PREDICT_FALSE (n_alloc == 0))
	{
	  vlib_error_count (vm, node->node_index,
			    MRVL_PP2_INPUT_ERROR_BUFFER_ALLOC, 1);
	  goto done;
	}

      while (i--)
	{
	  u32 bi0 = bi[0];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi0);
	  e->buff.addr = vlib_buffer_get_pa (vm, b) - 64;
	  e->buff.cookie = bi0;
	  e->bpool = inq->bpool;
	  e++;
	  bi++;
	}

      i = n_alloc;
      if (PREDICT_FALSE (pp2_bpool_put_buffs (ptd->hif, ptd->bre, &i)))
	{
	  vlib_error_count (vm, node->node_index,
			    MRVL_PP2_INPUT_ERROR_BPOOL_PUT_BUFFS, 1);
	  vlib_buffer_free (vm, ptd->bi, n_alloc);
	  goto done;
	}

      if (PREDICT_FALSE (i != n_alloc))
	vlib_buffer_free (vm, ptd->bi + i, n_alloc - i);

      n_bufs -= i;

      /*
       * If we had to return buffers just exit the loop we are churning the
       * end of buffer space
       */
      if (n_alloc != alloc_size)
	break;
    }

done:
  if (n_rx_packets)
    mrvl_pp2_pkt_debug ("%s: %u ppio[%u] port %u n_rx_packets %u",
			__FUNCTION__, ppif->sw_if_index, ppif->ppio->pp2_id,
			ppif->ppio->port_id, n_rx_packets);
  return n_rx_packets;
}

VLIB_NODE_FN(mrvl_pp2_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
  u32 n_rx = 0;
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    mrvl_pp2_if_t *ppif;
    ppif = vec_elt_at_index (ppm->interfaces, dq->dev_instance);
    if (ppif->flags & MRVL_PP2_IF_F_ADMIN_UP)
      n_rx += mrvl_pp2_device_input_inline (vm, node, frame, ppif,
					    dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mrvl_pp2_input_node) = {
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .name = "mrvl-pp2-input",
  .sibling_of = "device-input",
  .format_trace = format_mrvl_pp2_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = MRVL_PP2_INPUT_N_ERROR,
  .error_strings = mrvl_pp2_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

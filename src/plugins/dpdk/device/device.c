/*
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
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <assert.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

#define foreach_dpdk_tx_func_error			\
  _(BAD_RETVAL, "DPDK tx function returned an error")	\
  _(PKT_DROP, "Tx packet drops (dpdk tx failure)")

typedef enum
{
#define _(f,s) DPDK_TX_FUNC_ERROR_##f,
  foreach_dpdk_tx_func_error
#undef _
    DPDK_TX_FUNC_N_ERROR,
} dpdk_tx_func_error_t;

static char *dpdk_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_dpdk_tx_func_error
#undef _
};

static clib_error_t *
dpdk_add_del_mac_address (vnet_hw_interface_t * hi,
			  const u8 * address, u8 is_add)
{
  int error;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  if (is_add)
    error = rte_eth_dev_mac_addr_add (xd->port_id,
				      (struct rte_ether_addr *) address, 0);
  else
    error = rte_eth_dev_mac_addr_remove (xd->port_id,
					 (struct rte_ether_addr *) address);

  if (error)
    {
      return clib_error_return (0, "mac address add/del failed: %d", error);
    }

  return NULL;
}

static clib_error_t *
dpdk_set_mac_address (vnet_hw_interface_t * hi,
		      const u8 * old_address, const u8 * address)
{
  int error;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  error = rte_eth_dev_default_mac_addr_set (xd->port_id, (void *) address);

  if (error)
    {
      return clib_error_return (0, "mac address set failed: %d", error);
    }
  else
    {
      vec_reset_length (xd->default_mac_address);
      vec_add (xd->default_mac_address, address, sizeof (mac_address_t));
      return NULL;
    }
}

static void
dpdk_tx_trace_buffer (dpdk_main_t * dm, vlib_node_runtime_t * node,
		      dpdk_device_t * xd, u16 queue_id,
		      vlib_buffer_t * buffer)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_tx_trace_t *t0;
  struct rte_mbuf *mb;
  vlib_buffer_t *cb;
  u32 i, extra = 0;

  for (cb = buffer; (cb->flags & VLIB_BUFFER_NEXT_PRESENT);
       cb = vlib_get_buffer (vm, cb->next_buffer))
    extra++;

  mb = rte_mbuf_from_vlib_buffer (buffer);

  t0 =
    vlib_add_trace (vm, node, buffer,
		    sizeof (t0[0]) + sizeof (t0->chains[0]) * extra);
  t0->queue_index = queue_id;
  t0->device_index = xd->device_index;
  t0->buffer_index = vlib_get_buffer_index (vm, buffer);
  t0->tail_length = 0;

  /* Copy original mbuf structure */
  clib_memcpy_fast (&t0->mb, mb, sizeof (t0->mb));

  /* Copy original vlib buffer structure except for pre_data area tail */
  clib_memcpy_fast (&t0->buffer, buffer,
		    sizeof (buffer[0]) - sizeof (buffer->pre_data));

  /* Copy 1st part of vib buffer's notion of packet to copy's pre_data area */
  clib_memcpy_fast (t0->buffer.pre_data,
		    vlib_buffer_get_current_ind (buffer),
		    clib_min (sizeof (t0->buffer.pre_data),
			      t0->buffer.current_length));

  /*
   * If packet is bigger than pre_data[], copy tail of packet to 
   * tail of pre_data[]
   */
  /* Copy the last N bytes. */
  if (t0->buffer.current_length > sizeof (t0->buffer.pre_data))
    {
      u8 tlen = 32;	/* arbitrary amount of pre_data */

      ASSERT(tlen <= sizeof (t0->buffer.pre_data));
      t0->tail_length = tlen;
      clib_memcpy_fast (
	  t0->buffer.pre_data + sizeof (t0->buffer.pre_data) - tlen,
	  vlib_buffer_get_current_ind (buffer) + buffer->current_length - tlen,
	  tlen);
    }

  /* now copy the chained buffers and data */
  for (i = 0; i < extra; i++)
    {
      t0->chains[i].buffer_index = buffer->next_buffer;
      buffer = vlib_get_buffer (vm, buffer->next_buffer);
      mb = rte_mbuf_from_vlib_buffer (buffer);
      clib_memcpy_fast (&t0->chains[i].mb, mb, sizeof (t0->mb));
      clib_memcpy_fast (&t0->chains[i].buffer, buffer,
			sizeof (buffer[0]) - sizeof (buffer->pre_data));
      clib_memcpy_fast (t0->chains[i].buffer.pre_data,
			mb->buf_addr + mb->data_off,
			clib_min (sizeof(t0->chains[i].buffer.pre_data),
			  mb->data_len));
    }
}

/*
 * This function calls the dpdk's tx_burst function to transmit the packets.
 * It manages a lock per-device if the device does not
 * support multiple queues. It returns the number of packets untransmitted
 * If all packets are transmitted (the normal case), the function returns 0.
 */
static_always_inline
  u32 tx_burst_vector_internal (vlib_main_t * vm,
				dpdk_device_t * xd,
				struct rte_mbuf **mb, u32 n_left)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_tx_queue_t *txq;
  u32 n_retry;
  int n_sent = 0;
  int queue_id;

  n_retry = 16;
  queue_id = vm->thread_index % xd->tx_q_used;
  txq = vec_elt_at_index (xd->tx_queues, queue_id);

  do
    {
      clib_spinlock_lock_if_init (&txq->lock);

      if (PREDICT_TRUE (xd->flags & DPDK_DEVICE_FLAG_PMD))
	{
	  /* no wrap, transmit in one burst */
	  n_sent = rte_eth_tx_burst (xd->port_id, queue_id, mb, n_left);
	  n_retry--;
#if DPDK_ENABLE_TX_BURST_ELOG
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (event_enc_in) = {
                                              .format = "dpdk-tx-burst tosend %d sent %d retry %d",
                                              .format_args = "i4i4i4",
          };
          /* *INDENT-ON* */
	  u32 *esd = DPDK_ELOG_CURRENT_THREAD (event_enc_in);
	  *esd++ = n_left;
	  *esd++ = n_sent;
	  *esd++ = n_retry;
#endif
	}
      else
	{
	  ASSERT (0);
	  n_sent = 0;
	}

      clib_spinlock_unlock_if_init (&txq->lock);

      if (PREDICT_FALSE (n_sent < 0))
	{
	  // emit non-fatal message, bump counter
	  vnet_main_t *vnm = dm->vnet_main;
	  vnet_interface_main_t *im = &vnm->interface_main;
	  u32 node_index;

	  node_index = vec_elt_at_index (im->hw_interfaces,
					 xd->hw_if_index)->tx_node_index;

	  vlib_error_count (vm, node_index, DPDK_TX_FUNC_ERROR_BAD_RETVAL, 1);
	  return n_left;	// untransmitted packets
	}
      n_left -= n_sent;
      mb += n_sent;
    }
  while (n_sent && n_left && (n_retry > 0));

  return n_left;
}

static_always_inline __clib_unused void
dpdk_prefetch_buffer (vlib_main_t * vm, struct rte_mbuf *mb)
{
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  CLIB_PREFETCH (mb, sizeof (struct rte_mbuf), STORE);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline void
dpdk_buffer_tx_offload (dpdk_device_t * xd, vlib_buffer_t * b,
			struct rte_mbuf *mb)
{
  u32 ip_cksum = b->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
  u32 tcp_cksum = b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
  u32 udp_cksum = b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  int is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  u32 tso = b->flags & VNET_BUFFER_F_GSO;
  u64 ol_flags;

  /* Is there any work for us? */
  if (PREDICT_TRUE ((ip_cksum | tcp_cksum | udp_cksum | tso) == 0))
    return;

  mb->l2_len = vnet_buffer (b)->l3_hdr_offset - b->current_data;
  mb->l3_len = vnet_buffer (b)->l4_hdr_offset -
    vnet_buffer (b)->l3_hdr_offset;
  mb->outer_l3_len = 0;
  mb->outer_l2_len = 0;
  ol_flags = is_ip4 ? PKT_TX_IPV4 : PKT_TX_IPV6;
  ol_flags |= ip_cksum ? PKT_TX_IP_CKSUM : 0;
  ol_flags |= tcp_cksum ? PKT_TX_TCP_CKSUM : 0;
  ol_flags |= udp_cksum ? PKT_TX_UDP_CKSUM : 0;
  ol_flags |= tso ? (tcp_cksum ? PKT_TX_TCP_SEG : PKT_TX_UDP_SEG) : 0;

  if (tso)
    {
      mb->l4_len = vnet_buffer2 (b)->gso_l4_hdr_sz;
      mb->tso_segsz = vnet_buffer2 (b)->gso_size;
    }

  mb->ol_flags |= ol_flags;

  /* we are trying to help compiler here by using local ol_flags with known
     state of all flags */
  if (xd->flags & DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM)
    rte_net_intel_cksum_flags_prepare (mb, ol_flags);
}

/*
 * Transmits the packets on the frame to the interface associated with the
 * node. It first copies packets on the frame to a per-thread arrays
 * containing the rte_mbuf pointers.
 */
VNET_DEVICE_CLASS_TX_FN (dpdk_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * f)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, rd->dev_instance);
  u32 n_packets = f->n_vectors;
  u32 n_left;
  u32 thread_index = vm->thread_index;
  int queue_id = thread_index;
  u32 tx_pkts = 0, all_or_flags = 0;
  dpdk_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);
  struct rte_mbuf **mb;
  vlib_buffer_t *b[4];

  ASSERT (n_packets <= VLIB_FRAME_SIZE);

  /* calculate rte_mbuf pointers out of buffer indices */
  vlib_get_buffers_with_offset (vm, vlib_frame_vector_args (f),
				(void **) ptd->mbufs, n_packets,
				-(i32) sizeof (struct rte_mbuf));

  n_left = n_packets;
  mb = ptd->mbufs;

#if (CLIB_N_PREFETCHES >= 8)
  while (n_left >= 8)
    {
      u32 or_flags;

      dpdk_prefetch_buffer (vm, mb[4]);
      dpdk_prefetch_buffer (vm, mb[5]);
      dpdk_prefetch_buffer (vm, mb[6]);
      dpdk_prefetch_buffer (vm, mb[7]);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);
      b[2] = vlib_buffer_from_rte_mbuf (mb[2]);
      b[3] = vlib_buffer_from_rte_mbuf (mb[3]);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;
      all_or_flags |= or_flags;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      if (or_flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  dpdk_validate_rte_mbuf (vm, b[0], 1);
	  dpdk_validate_rte_mbuf (vm, b[1], 1);
	  dpdk_validate_rte_mbuf (vm, b[2], 1);
	  dpdk_validate_rte_mbuf (vm, b[3], 1);
	}
      else
	{
	  dpdk_validate_rte_mbuf (vm, b[0], 0);
	  dpdk_validate_rte_mbuf (vm, b[1], 0);
	  dpdk_validate_rte_mbuf (vm, b[2], 0);
	  dpdk_validate_rte_mbuf (vm, b[3], 0);
	}

      if (PREDICT_FALSE ((xd->flags & DPDK_DEVICE_FLAG_TX_OFFLOAD) &&
			 (or_flags &
			  (VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_IP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))))
	{
	  dpdk_buffer_tx_offload (xd, b[0], mb[0]);
	  dpdk_buffer_tx_offload (xd, b[1], mb[1]);
	  dpdk_buffer_tx_offload (xd, b[2], mb[2]);
	  dpdk_buffer_tx_offload (xd, b[3], mb[3]);
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[0]);
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[1]);
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[2]);
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[3]);
	}

      mb += 4;
      n_left -= 4;
    }
#elif (CLIB_N_PREFETCHES >= 4)
  while (n_left >= 4)
    {
      vlib_buffer_t *b2, *b3;
      u32 or_flags;

      CLIB_PREFETCH (mb[2], CLIB_CACHE_LINE_BYTES, STORE);
      CLIB_PREFETCH (mb[3], CLIB_CACHE_LINE_BYTES, STORE);
      b2 = vlib_buffer_from_rte_mbuf (mb[2]);
      CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, LOAD);
      b3 = vlib_buffer_from_rte_mbuf (mb[3]);
      CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, LOAD);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);

      or_flags = b[0]->flags | b[1]->flags;
      all_or_flags |= or_flags;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);

      if (or_flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  dpdk_validate_rte_mbuf (vm, b[0], 1);
	  dpdk_validate_rte_mbuf (vm, b[1], 1);
	}
      else
	{
	  dpdk_validate_rte_mbuf (vm, b[0], 0);
	  dpdk_validate_rte_mbuf (vm, b[1], 0);
	}

      if (PREDICT_FALSE ((xd->flags & DPDK_DEVICE_FLAG_TX_OFFLOAD) &&
			 (or_flags &
			  (VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_IP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))))
	{
	  dpdk_buffer_tx_offload (xd, b[0], mb[0]);
	  dpdk_buffer_tx_offload (xd, b[1], mb[1]);
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[0]);
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[1]);
	}

      mb += 2;
      n_left -= 2;
    }
#endif

  while (n_left > 0)
    {
      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      all_or_flags |= b[0]->flags;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      dpdk_validate_rte_mbuf (vm, b[0], 1);
      dpdk_buffer_tx_offload (xd, b[0], mb[0]);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	  dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[0]);

      mb++;
      n_left--;
    }

  /* transmit as many packets as possible */
  tx_pkts = n_packets = mb - ptd->mbufs;
  n_left = tx_burst_vector_internal (vm, xd, ptd->mbufs, n_packets);

  {
    /* If there is no callback then drop any non-transmitted packets */
    if (PREDICT_FALSE (n_left))
      {
	tx_pkts -= n_left;
	vlib_simple_counter_main_t *cm;
	vnet_main_t *vnm = vnet_get_main ();

	cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			       VNET_INTERFACE_COUNTER_TX_ERROR);

	vlib_increment_simple_counter (cm, thread_index, xd->sw_if_index,
				       n_left);

	vlib_error_count (vm, node->node_index, DPDK_TX_FUNC_ERROR_PKT_DROP,
			  n_left);

	while (n_left--)
	  rte_pktmbuf_free (ptd->mbufs[n_packets - n_left - 1]);
      }
  }

  return tx_pkts;
}

static void
dpdk_clear_hw_interface_counters (u32 instance)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, instance);

  rte_eth_stats_reset (xd->port_id);
  rte_eth_xstats_reset (xd->port_id);
}

static clib_error_t *
dpdk_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hif->dev_instance);

  if (xd->flags & DPDK_DEVICE_FLAG_PMD_INIT_FAIL)
    return clib_error_return (0, "Interface not initialized");

  if (is_up)
    {
      if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) == 0)
	dpdk_device_start (xd);
      xd->flags |= DPDK_DEVICE_FLAG_ADMIN_UP;
      f64 now = vlib_time_now (dm->vlib_main);
      dpdk_update_counters (xd, now);
      dpdk_update_link_state (xd, now);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, 0);
      if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) != 0)
	dpdk_device_stop (xd);
      xd->flags &= ~DPDK_DEVICE_FLAG_ADMIN_UP;
    }

  return /* no error */ 0;
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void
dpdk_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  dpdk_main_t *xm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      xd->per_interface_next_index = node_index;
      return;
    }

  xd->per_interface_next_index =
    vlib_node_add_next (xm->vlib_main, dpdk_input_node.index, node_index);
}


static clib_error_t *
dpdk_subif_add_del_function (vnet_main_t * vnm,
			     u32 hw_if_index,
			     struct vnet_sw_interface_t *st, int is_add)
{
  dpdk_main_t *xm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  vnet_sw_interface_t *t = (vnet_sw_interface_t *) st;
  int r, vlan_offload;
  u32 prev_subifs = xd->num_subifs;
  clib_error_t *err = 0;

  if (is_add)
    xd->num_subifs++;
  else if (xd->num_subifs)
    xd->num_subifs--;

  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    goto done;

  /* currently we program VLANS only for IXGBE VF and I40E VF */
  if ((xd->pmd != VNET_DPDK_PMD_IXGBEVF) && (xd->pmd != VNET_DPDK_PMD_I40EVF))
    goto done;

  if (t->sub.eth.flags.no_tags == 1)
    goto done;

  if ((t->sub.eth.flags.one_tag != 1) || (t->sub.eth.flags.exact_match != 1))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "unsupported VLAN setup");
      goto done;
    }

  vlan_offload = rte_eth_dev_get_vlan_offload (xd->port_id);
  vlan_offload |= ETH_VLAN_FILTER_OFFLOAD;

  if ((r = rte_eth_dev_set_vlan_offload (xd->port_id, vlan_offload)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_set_vlan_offload[%d]: err %d",
			       xd->port_id, r);
      goto done;
    }


  if ((r =
       rte_eth_dev_vlan_filter (xd->port_id,
				t->sub.eth.outer_vlan_id, is_add)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_vlan_filter[%d]: err %d",
			       xd->port_id, r);
      goto done;
    }

done:
  if (xd->num_subifs)
    xd->flags |= DPDK_DEVICE_FLAG_HAVE_SUBIF;
  else
    xd->flags &= ~DPDK_DEVICE_FLAG_HAVE_SUBIF;

  return err;
}

static clib_error_t *
dpdk_interface_set_rss_queues (struct vnet_main_t *vnm,
			       struct vnet_hw_interface_t *hi,
			       clib_bitmap_t * bitmap)
{
  dpdk_main_t *xm = &dpdk_main;
  u32 hw_if_index = hi->hw_if_index;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  clib_error_t *err = 0;
  struct rte_eth_rss_reta_entry64 *reta_conf = NULL;
  struct rte_eth_dev_info dev_info;
  u16 *reta = NULL;
  u16 *valid_queue = NULL;
  u16 valid_queue_count = 0;
  uint32_t i, j;
  uint32_t ret;

  rte_eth_dev_info_get (xd->port_id, &dev_info);

  /* parameter check */
  if (clib_bitmap_count_set_bits (bitmap) == 0)
    {
      err = clib_error_return (0, "must assign at least one valid rss queue");
      goto done;
    }

  if (clib_bitmap_count_set_bits (bitmap) > dev_info.nb_rx_queues)
    {
      err = clib_error_return (0, "too many rss queues");
      goto done;
    }

  /* new RETA */
  reta = clib_mem_alloc (dev_info.reta_size * sizeof (*reta));
  if (reta == NULL)
    {
      err = clib_error_return (0, "clib_mem_alloc failed");
      goto done;
    }

  clib_memset (reta, 0, dev_info.reta_size * sizeof (*reta));

  valid_queue_count = 0;
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, bitmap, ({
    if (i >= dev_info.nb_rx_queues)
      {
        err = clib_error_return (0, "illegal queue number");
        goto done;
      }
    reta[valid_queue_count++] = i;
  }));
  /* *INDENT-ON* */

  /* check valid_queue_count not zero, make coverity happy */
  if (valid_queue_count == 0)
    {
      err = clib_error_return (0, "must assign at least one valid rss queue");
      goto done;
    }

  valid_queue = reta;
  for (i = valid_queue_count, j = 0; i < dev_info.reta_size; i++, j++)
    {
      j = j % valid_queue_count;
      reta[i] = valid_queue[j];
    }

  /* update reta table */
  reta_conf =
    (struct rte_eth_rss_reta_entry64 *) clib_mem_alloc (dev_info.reta_size /
							RTE_RETA_GROUP_SIZE *
							sizeof (*reta_conf));
  if (reta_conf == NULL)
    {
      err = clib_error_return (0, "clib_mem_alloc failed");
      goto done;
    }

  clib_memset (reta_conf, 0,
	       dev_info.reta_size / RTE_RETA_GROUP_SIZE *
	       sizeof (*reta_conf));

  for (i = 0; i < dev_info.reta_size; i++)
    {
      uint32_t reta_id = i / RTE_RETA_GROUP_SIZE;
      uint32_t reta_pos = i % RTE_RETA_GROUP_SIZE;

      reta_conf[reta_id].mask = UINT64_MAX;
      reta_conf[reta_id].reta[reta_pos] = reta[i];
    }

  ret =
    rte_eth_dev_rss_reta_update (xd->port_id, reta_conf, dev_info.reta_size);
  if (ret)
    {
      err = clib_error_return (0, "rte_eth_dev_rss_reta_update err %d", ret);
      goto done;
    }

done:
  if (reta)
    clib_mem_free (reta);
  if (reta_conf)
    clib_mem_free (reta_conf);

  return err;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (dpdk_device_class) = {
  .name = "dpdk",
  .tx_function_n_errors = DPDK_TX_FUNC_N_ERROR,
  .tx_function_error_strings = dpdk_tx_func_error_strings,
  .format_device_name = format_dpdk_device_name,
  .format_device = format_dpdk_device,
  .format_tx_trace = format_dpdk_tx_trace,
  .clear_counters = dpdk_clear_hw_interface_counters,
  .admin_up_down_function = dpdk_interface_admin_up_down,
  .subif_add_del_function = dpdk_subif_add_del_function,
  .rx_redirect_to_node = dpdk_set_interface_next_node,
  .mac_addr_change_function = dpdk_set_mac_address,
  .mac_addr_add_del_function = dpdk_add_del_mac_address,
  .format_flow = format_dpdk_flow,
  .flow_ops_function = dpdk_flow_ops_fn,
  .set_rss_queues_function = dpdk_interface_set_rss_queues,
};
/* *INDENT-ON* */

#define UP_DOWN_FLAG_EVENT 1

static uword
admin_up_down_process (vlib_main_t * vm,
		       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  clib_error_t *error = 0;
  uword event_type;
  uword *event_data = 0;
  u32 sw_if_index;
  u32 flags;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      dpdk_main.admin_up_down_in_progress = 1;

      switch (event_type)
	{
	case UP_DOWN_FLAG_EVENT:
	  {
	    if (vec_len (event_data) == 2)
	      {
		sw_if_index = event_data[0];
		flags = event_data[1];
		error =
		  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index,
					       flags);
		clib_error_report (error);
	      }
	  }
	  break;
	}

      vec_reset_length (event_data);

      dpdk_main.admin_up_down_in_progress = 0;

    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (admin_up_down_process_node) = {
    .function = admin_up_down_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "admin-up-down-process",
    .process_log2_n_stack_bytes = 17,  // 256KB
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * May 18 2019, Christian E. Hopps <chopps@labn.net>
 *
 * Copyright (c) 2019, LabN Consulting, L.L.C.
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
#include <sys/queue.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/ring.h>
#include <vnet/ipsec/esp.h>
#include <iptfs/ipsec_iptfs.h>
#include <iptfs/iptfs_zpool.h>

// 20200423 disabled for armada
// #undef ASSERT
// #define ASSERT iptfs_assert

///* XXX: disable this for now */
//#undef iptfs_pkt_debug_s
//#undef IPTFS_DEBUG_CORRUPTION
//#define iptfs_pkt_debug_s(x, ...)

/* XXX I think we will need to pad packets to align headers */
/* XXX this min space has to be 1 right now, changing it requires re-exmaining
 * the uses */
#define IPTFS_ENCAP_MIN_AVAIL_SPACE 1

#define foreach_iptfs_encap_next   \
  _ (DROP, "error-drop")           \
  _ (ICMP4, "ip4-icmp-error")      \
  _ (ICMP6, "ip6-icmp-error")      \
  _ (ESP4_ENCRYPT, "esp4-encrypt") \
  _ (ESP6_ENCRYPT, "esp6-encrypt") \
  _ (PACER,                        \
     "iptfs-pacer") /* This is never used except to get a trace buffer */

typedef enum
{
#define _(v, s) IPTFS_ENCAP_NEXT_##v,
  foreach_iptfs_encap_next
#undef _
      IPTFS_ENCAP_N_NEXT,
} iptfs_encap_next_t;

#define foreach_iptfs_encap_error                                            \
  _ (IP4_MTU, "IPTFS-encap-warn IPv4 packets MTU exceeded")                  \
  _ (IP6_MTU, "IPTFS-encap-warn IPv4 packets MTU exceeded")                  \
  _ (UNKNONW_TYPE, "IPTFS-encap-warn unknown packet type for encapsulation") \
  _ (NO_BUF, "IPTFS-encap-err out-of-buffers")                               \
  _ (BAD_LEN, "IPTFS-encap-err ip length larger than received data")

typedef enum
{
#define _(sym, str) IPTFS_ENCAP_ERROR_##sym,
  foreach_iptfs_encap_error
#undef _
      IPTFS_ENCAP_N_ERROR,
} iptfs_encap_error_t;

static char *iptfs_encap_error_strings[] = {
#define _(sym, string) string,
    foreach_iptfs_encap_error
#undef _
};

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
iptfs_encap_backend_update ()
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;

  vlib_node_add_next_with_slot (vm, iptfs_encap_enq_node.index,
				im->esp4_encrypt_node_index,
				IPTFS_ENCAP_NEXT_ESP4_ENCRYPT);
  vlib_node_add_next_with_slot (vm, iptfs_encap_enq_node.index,
				im->esp6_encrypt_node_index,
				IPTFS_ENCAP_NEXT_ESP6_ENCRYPT);

  vlib_node_add_next_with_slot (vm, iptfs_encap4_tun_node.index,
				im->esp4_encrypt_node_index,
				IPTFS_ENCAP_NEXT_ESP4_ENCRYPT);

  vlib_node_add_next_with_slot (vm, iptfs_encap6_tun_node.index,
				im->esp6_encrypt_node_index,
				IPTFS_ENCAP_NEXT_ESP6_ENCRYPT);

  if (!vlib_num_workers ())
    return 0;

  /*
   * We need handoff queues
   */

  u32 next_index;
  uword *p;
  next_index = im->esp4_encrypt_node_index;
  p = hash_get (tfsm->handoff_queue_by_index, next_index);
  if (p)
    tfsm->encap4_only_frame_queue = p[0];
  else
    {
      tfsm->encap4_only_frame_queue =
	  vlib_frame_queue_main_init (next_index,
				      IPTFS_ENCAP_HANDOFF_QUEUE_SIZE);
      hash_set (tfsm->handoff_queue_by_index, next_index,
		tfsm->encap4_only_frame_queue);
    }

  next_index = im->esp6_encrypt_node_index;
  p = hash_get (tfsm->handoff_queue_by_index, next_index);
  if (p)
    tfsm->encap6_only_frame_queue = p[0];
  else
    {
      tfsm->encap6_only_frame_queue =
	  vlib_frame_queue_main_init (next_index,
				      IPTFS_ENCAP_HANDOFF_QUEUE_SIZE);
      hash_set (tfsm->handoff_queue_by_index, next_index,
		tfsm->encap6_only_frame_queue);
    }

  return 0;
}

/* packet trace format function */
u8 *
format_iptfs_encap_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  u32 *sa_index = va_arg (*args, u32 *);
  return format (s, "sa_index: %u", *sa_index);
}
#endif

static inline void
iptfs_encap_trace_new_buffer (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_buffer_t *b0, u32 sa_index)
{
  uword n_trace = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (n_trace))
    {
      vlib_trace_buffer (vm, node, IPTFS_ENCAP_NEXT_PACER, b0,
			 /* follow_chain */ 1);
      *(u32 *)vlib_add_trace (vm, node, b0, sizeof (u32)) = sa_index;
      vlib_set_trace_count (vm, node, n_trace - 1);
    }
}

static inline u16
iptfs_encap_buflen_fixup (vlib_main_t *vm, vlib_buffer_t *b)
{
  u32 buflen = vlib_buffer_length_in_chain (vm, b);
  u8 *data = vlib_buffer_get_current (b);
  ip4_header_t *ip;
  ip6_header_t *ip6;
  u16 iplen;

  switch (*data & 0xF0)
    {
    case 0x40:
      ip = (ip4_header_t *)data;
      iplen = clib_net_to_host_u16 (ip->length);
      break;
    case 0x60:
      ip6 = (ip6_header_t *)data;
      iplen =
	  clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);
      break;
    default:
      ASSERT (0);
      return 0;
    }
  if (PREDICT_FALSE ((iplen > buflen)))
    {
      clib_warning ("%s Drop: BAD lengths buflen %u iplen %u", __FUNCTION__,
		    buflen, iplen);
      return 0;
    }
  else if (buflen > iplen)
    /* XXX not valid for chain -- will we ever have a chain in this situation
     * (tiny packet?) */
    b->current_length -= (buflen - iplen);
  return b->current_length;
}

static inline u32
iptfs_icmp_unreach (vlib_main_t *CLIB_UNUSED (vm), vlib_node_runtime_t *node,
		    vlib_buffer_t *b, u16 mtu, u8 *data)
{
  vnet_buffer_opaque_t *bo = vnet_buffer (b);

  if ((*data & 0xF0) == 0x40)
    {
      ip4_header_t *ip = (ip4_header_t *)data;
      if (!(ip->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT)))
	{
	  iptfs_debug ("%s: Packet exceeds MTU but no DF flag", __FUNCTION__);
	  return IPTFS_ENCAP_NEXT_DROP;
	}
      iptfs_debug ("%s: IP4 Packet exceeds MTU %u sending ICMP unreach "
		   "sw_if_index %u, %u",
		   __FUNCTION__, mtu, bo->sw_if_index[VLIB_RX],
		   bo->sw_if_index[VLIB_TX]);
      icmp4_error_set_vnet_buffer (
	  b, ICMP4_destination_unreachable,
	  ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
	  mtu);
      bo->sw_if_index[VLIB_TX] = ~0;
      b->error = node->errors[IPTFS_ENCAP_ERROR_IP4_MTU];
      return IPTFS_ENCAP_NEXT_ICMP4;
    }
  else
    {
      ASSERT ((*data & 0xF0) == 0x60);
      iptfs_debug ("%s: IP6 Packet exceeds MTU %u sending ICMP unreach",
		   __FUNCTION__, mtu);
      icmp6_error_set_vnet_buffer (b, ICMP6_destination_unreachable,
				   ICMP6_packet_too_big, mtu);
      bo->sw_if_index[VLIB_TX] = ~0;
      b->error = node->errors[IPTFS_ENCAP_ERROR_IP6_MTU];
      return IPTFS_ENCAP_NEXT_ICMP6;
    }
}

always_inline u32
iptfs_check_refill_encap_zpool (vlib_main_t *vm, iptfs_sa_data_t *satd,
				u32 sa_index)
{
  iptfs_zpool_t *zpool = satd->tfs_encap.zpool;
  u32 remaining = iptfs_zpool_get_avail (zpool);

  if (PREDICT_TRUE (satd->tfs_encap_zpool_running))
    return remaining;

  /* This is only the case when we are running on main only */
  if (PREDICT_FALSE (remaining < zpool->trigger))
    iptfs_zpool_ping_nobuf (vm, sa_index, satd);

  return remaining;
}

static inline u16
iptfs_encap_reuse_buffer (vlib_buffer_t *b, iptfs_sa_data_t *satd)
{
  vnet_buffer_opaque_t *bdata = vnet_buffer (b);
  bdata->ipsec.sad_index = iptfs_sa_data_to_index (satd);
  bdata->ipsec.iptfs_reused_user = true;
  bdata->sw_if_index[VLIB_RX] = 0;
  bdata->sw_if_index[VLIB_TX] = 0;

  /* Clear any user flags (e.g., offload checksum valid etc) */
  b->flags &= VLIB_BUFFER_FLAGS_ALL;

  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  /* This isn't always zero'd, and the code expects it to be */
  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    b->total_length_not_including_first_buffer = 0;

  /* add in the zero'd iptfs header */
  u16 hlen = iptfs_sa_data_hdrlen (satd);
  ipsec_iptfs_basic_header_t *h = vlib_buffer_push_uninit (b, hlen);
  clib_memset (h, 0, hlen);
  if (satd->tfs_cc)
    h->subtype = IPTFS_SUBTYPE_CC;

  return hlen;
}

static inline vlib_buffer_t *
iptfs_encap_get_in_progress (vlib_main_t *vm, iptfs_sa_data_t *satd,
			     vlib_buffer_t **lastb)
{
  if (lastb)
    *lastb = satd->tfs_encap.inlastb;
  return vlib_get_buffer (vm, satd->tfs_encap.infirst);
}

/*
 * Set the queue available of the last queued buffer (b and avail), if this
 * doesn't meet the minimum then pad out the buffer and reset the queue avail
 * to 0.
 */
static inline bool
iptfs_encap_fixup_buf_and_avail (vlib_main_t *vm, iptfs_sa_data_t *satd,
				 u16 avail, bool force_done)
{
  if (!force_done && avail >= IPTFS_ENCAP_MIN_AVAIL_SPACE)
    /* Update available space in top packet */
    satd->tfs_encap.q_packet_avail = avail;
  else
    {
      /* force_done (avail or not avail) || !avail */

      vlib_buffer_t *lastb;
      u32 first = satd->tfs_encap.infirst;
      vlib_buffer_t *firstb = iptfs_encap_get_in_progress (vm, satd, &lastb);

      satd->tfs_encap.q_packet_avail = 0;

      /* pad to end */
      if (avail)
	{
	  /*
	   * XXX this going to corrupt a straddle if avail is not 0 (i.e., we
	   * have som min avail required which we dont' right now
	   */
	  /* XXX we need to zero rest, or buffer returns do it */
	  ASSERT (!(lastb->flags & VLIB_BUFFER_INDIRECT));
	  *vlib_buffer_get_tail (lastb) = 0;
	  lastb->current_length += avail;
	}

      if (firstb == lastb)
	{
	  ASSERT (lastb->current_length ==
		  satd->tfs_encap.tfs_ipsec_payload_size);
	  ASSERT ((!(firstb->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID)) ||
		  firstb->total_length_not_including_first_buffer == 0);
	}
      else
	{
	  // Add avail here (which we added to lastb->current_length above.
	  firstb->total_length_not_including_first_buffer += avail;
	  ASSERT (firstb->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
	  ASSERT (firstb->current_length +
		      firstb->total_length_not_including_first_buffer ==
		  satd->tfs_encap.tfs_ipsec_payload_size);
	}

      /* move the inprogress packet to the outq */
      if (!iptfs_bufq_enqueue (&satd->tfs_encap.outq, first,
			       vnet_buffer (firstb)->ipsec.tfs_actual_data))
	{
	  clib_warning ("%s: couldn't enqueue in progress packet!",
			__FUNCTION__);
	  return false;
	}
      satd->tfs_encap.infirst = ~0u;
      satd->tfs_encap.inlastb = NULL;
      // satd->tfs_encap.inccount = 0;
    }
  return true;
}

static inline bool
iptfs_encap_validate_queue_and_buffers (vlib_main_t *vm, u32 sa_index,
					iptfs_sa_data_t *satd, u16 remaining,
					u16 payspace, bool chaining)
{

  uint pneed = remaining / payspace;
  uint slop = remaining % payspace;
  uint leftover = slop ? 1 : 0;
  uint bneed = 0;

  /*
   * If we have no space for queuing new packets fail early
   *
   * We check for an extra slot to handle any in-progress packet we might
   * need to also enqueue.
   */
  if (iptfs_bufq_avail (&satd->tfs_encap.outq) < (pneed + leftover + 1))
    return false;

  if (!chaining)
    {
      bneed = pneed + leftover;
      if (!bneed)
	return true;
    }
  else
    {
      if (!remaining)
	return true;
      else
	{
	  /*
	   * Since we have more we will indirectly refer to the source so we
	   * need a buffer to terminate the first chain.
	   */
	  bneed += 1;

	  /*
	   * pneed is the number of whole packets we need. For each whole
	   * packet we need a header, and an indirect, and a footer buffer.
	   */
	  bneed += pneed * 3;

	  /*
	   * Finally deal with any leftover, if the leftover is within
	   * IPTFS_ENCAP_STRADDLE_COPY_OVER_INDRECT_SIZE, we will copy
	   * into the header buffer so we only need 1 buffer, otherwise
	   * we need 2 buffers for header and an indirect.
	   */
	  if (!slop)
	    ;
#ifdef IPTFS_ENCAP_COPY_AND_CHAIN
	  else if (slop <= IPTFS_ENCAP_STRADDLE_COPY_OVER_INDRECT_SIZE (satd))
	    bneed++;
#endif
	  else
	    bneed += 2;
	}
    }

  u32 pblen = iptfs_check_refill_encap_zpool (vm, satd, sa_index);
  if (bneed > pblen)
    {
      /* Log an event with our data for this run */
      ELOG_TYPE_DECLARE (e) = {
	  .format = "iptfs-encap-nobufs sa_index %d asked %d",
	  .format_args = "i4i4",
      };
      u32 *data = IPTFS_ELOG (e, satd->tfs_error_track);
      *data++ = sa_index;
      *data++ = bneed;
      return false;
    }

  vec_validate (satd->tfs_encap.buffers, bneed - 1);
  if (!iptfs_zpool_get_buffers (satd->tfs_encap.zpool, satd->tfs_encap.buffers,
				bneed, false))
    {
      vec_reset_length (satd->tfs_encap.buffers);
      return false;
    }
  _vec_len (satd->tfs_encap.buffers) = bneed;
  return true;
}

/*
 * Initialize an IPTFS indirect buffer for encap use.
 */
static inline vlib_buffer_t *
iptfs_init_chained_indirect_buffer (vlib_main_t *vm, u32 bi,
				    vlib_buffer_t *datab, u16 data_off,
				    u16 data_len)
{
#ifdef IPTFS_DEBUG_CORRUPTION
  static u8 numbers[] = {0,  1,	 2,  3,	 4,  5,	 6,  7,	 8,  9,	 10, 11, 12,
			 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
			 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
			 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
			 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63};
#endif
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);

  ASSERT (!(b->flags & (VLIB_BUFFER_FLAGS_ALL & ~VLIB_BUFFER_EXT_HDR_VALID)));

#ifdef IPTFS_DEBUG_CORRUPTION
#ifdef IPTFS_DEBUG
  /* Copy in some known data to see if, i.e., find bugs */
  clib_memcpy_fast (b->data, numbers, sizeof (numbers));
#endif
#endif
  // XXX: seeing this
  // vnet_buffer2 (b)->debug_magic = 0xc0edbabec0edbabe;
  // XXX: maybe only set this on first attach to this buffer check
  // refcount? vnet_buffer2 (datab)->debug_magic = 0xdeadbeafdeadbeaf;
  vlib_buffer_attach (vm, b, datab);
  b->current_data = data_off;
  b->current_length = data_len;
  return b;
}

static inline vlib_buffer_t *
iptfs_encap_add_empty_buffer (vlib_main_t *vm, vlib_buffer_t *lastb, u32 bi)
{
  /* XXX Do we need to do anything with total length valid here? */
  lastb->next_buffer = bi;
  lastb->flags |= VLIB_BUFFER_NEXT_PRESENT;

  lastb = vlib_get_buffer (vm, bi);
  /*
   * See iptfs_init_buffer.
   */
  ASSERT (lastb->current_data == 0);
  ASSERT (
      !(lastb->flags & (VLIB_BUFFER_FLAGS_ALL & ~VLIB_BUFFER_EXT_HDR_VALID)));
  /* Need to reset from full buffer of zeros to empty buffer */
  lastb->current_length = 0;
  return lastb;
}

static inline bool
iptfs_encap_add_packet (vlib_main_t *vm, vlib_node_runtime_t *node,
			u32 thread_index, u32 sa_index, iptfs_sa_data_t *satd,
			u32 bi0, vlib_buffer_t *b0, u32 **freeb,
			IPTFS_DBG_ARG (u8 **dbg))
{
  /*
   * Queue is locked. Grab top most buffer and add this buffer to it.
   * 1A) If queue is empty, own this buffer and use it.
   * 1B) else queue has a packet, use that packet and copy/reference this
   * buffer inside it. If this packet doesn't fit grab the all pad buffer
   * and add the rest of this packet to that.
   */
  iptfs_pkt_debug_s (dbg, "%s Entered: in thread %u", __FUNCTION__,
		     thread_index);
  u16 mtu = satd->tfs_encap.tfs_ipsec_payload_size;
  u32 b0flags = b0->flags;
  vlib_buffer_t *lastb;

  iptfs_assert (thread_index == satd->tfs_encap.encap_thread_index);

  /*
   * If nothing usable queued, re-use this buffer and queue it.
   */
  /* XXX: we don't actually handle chains in inner packets */
  // u16 chaincount;
  // u32 blen = vlib_buffer_length_in_chain_lb (vm, b0, &lastb, &chaincount);
  u32 blen = vlib_buffer_length_in_chain_lb (vm, b0, &lastb, NULL);
  u16 avail = satd->tfs_encap.q_packet_avail;
  u16 remaining = blen;
  u16 data_off;

  /*
   * Handle the case where we need to first close off an in-progress
   */
  u32 first = satd->tfs_encap.infirst;

  if (first != ~0u && PREDICT_FALSE (satd->tfs_df && (remaining > avail)))
    {
#ifdef IPTFS_DEBUG
#ifdef IPTFS_DEBUG_CORRUPTION
      vlib_buffer_t *cb = iptfs_encap_get_in_progress (vm, satd, NULL);

      /* If we are not fragmenting, and remaining > avail, close the
	 current buffer and start a new one */
      iptfs_pkt_debug_s (
	  dbg,
	  "%s: Have too small in-progress buffer for DF case mtu "
	  "%u cl %u avail %u remaining %u queueing encap_seq %llu",
	  __FUNCTION__, mtu, vlib_buffer_length_in_chain (vm, cb), avail,
	  remaining, satd->tfs_tx.encap_seq);
#endif
#endif
      /* move current packet to the queue */
      if (!iptfs_encap_fixup_buf_and_avail (vm, satd, avail, true))
	*(*freeb)++ = first;
#ifdef IPTFS_DEBUG_CORRUPTION
      else
	vnet_buffer_iptfs_esp_seq (cb) = satd->tfs_tx.encap_seq++;
#endif
      avail = 0;
    }

  /* We should never have an in-progress packet with nothing available in
   * it
   */
  ASSERT (satd->tfs_encap.infirst == ~0u || avail);

  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);

  /* We never leave it set < IPTFS_ENCAP_MIN_AVAIL_SPACE and not 0 */
  ASSERT (avail >= IPTFS_ENCAP_MIN_AVAIL_SPACE ||
	  satd->tfs_encap.q_packet_avail == 0);

  /* XXX this code is not ingress chain friendly! */
  ASSERT (!(b0->flags & VLIB_BUFFER_NEXT_PRESENT));

  const u16 payspace = mtu - iptfs_sa_data_hdrlen (satd);
  if (!avail)
    {
      /*--------------------------------------*/
      /* Start a new packet using user packet */
      /*--------------------------------------*/

      ASSERT (satd->tfs_encap.infirst == ~0u);
      ASSERT (satd->tfs_encap.inlastb == NULL);
      // ASSERT (satd->tfs_encap.inccount == 0);

      blen += iptfs_encap_reuse_buffer (b0, satd);

      /*
       * This code (to the end of the out conditional is identical to the
       * copy code except for the "true" passed to validate function. XXX
       * factor it.
       */
      if (blen < mtu)
	{
	  /* XXX: this code is not ok with IPTFS_ENCAP_MIN_AVAIL_SPACE >
	   * 1 */
	  avail = mtu - blen;
	  remaining = 0;

	  /* Save this as in-progress packet */
	  satd->tfs_encap.infirst = bi0;
	  satd->tfs_encap.inlastb = lastb;
	  ASSERT (lastb == b0); /* XXX not handling ingress chains */
	  // satd->tfs_encap.inccount = 1;
	}
      else
	{
	  avail = 0;
	  remaining = blen - mtu;

	  /* Verify we have enough space to finish sending the packet */
	  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
	  if (!iptfs_encap_validate_queue_and_buffers (vm, sa_index, satd,
						       remaining, payspace,
						       true))
	    {
	      iptfs_debug ("%s: FAIL: b0cl %u blen %u mtu %u Q ring avail %u",
			   __FUNCTION__, b0->current_length, blen, mtu,
			   iptfs_bufq_avail (&satd->tfs_encap.outq));
	      goto fail;
	    }

	  /* shrink buffer to MTU size */
	  b0->current_length -= remaining;
	  ASSERT (b0->current_length == mtu);
	}

#ifdef IPTFS_DEBUG_CORRUPTION
      /* Track the a sequence number to associate. */
      vnet_buffer_iptfs_esp_seq (b0) = satd->tfs_tx.encap_seq++;
#endif

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	*(u32 *)vlib_add_trace (vm, node, b0, sizeof (u32)) = sa_index;

      /* Track the amount of queue data this packet represents */
      vnet_buffer (b0)->ipsec.tfs_actual_data =
	  b0->current_length - iptfs_sa_data_hdrlen (satd);

      satd->tfs_encap.q_packet_avail = avail;

      if (remaining)
	{
	  /* We need to add a buffer to the end of this buffer chain as we
	     continue to use the original for indirect. */
	  (void)iptfs_encap_add_empty_buffer (
	      vm, lastb, vec_pop (satd->tfs_encap.buffers));

	  if (PREDICT_TRUE (lastb == b0))
	    {
	      /* We added the first chained buffer it's of zero length */
	      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      b0->total_length_not_including_first_buffer = 0;
	    }
	  else
	    ASSERT (b0->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);

	  /*
	   * We don't update tfs_encap.inlastb b/c we didn't set it above in
	   * the !avail case
	   */
	}

      /* Queue the full packet */
      if (!avail &&
	  !iptfs_bufq_enqueue (&satd->tfs_encap.outq, bi0,
			       vnet_buffer (b0)->ipsec.tfs_actual_data))
	{
	  clib_warning ("%s: failed to queue buffer %u", __FUNCTION__, bi0);
	  ASSERT (0); /* we verified this would succeed above */
	}

      if (!remaining)
	{
	  iptfs_pkt_debug_s (dbg,
			     "%s: Re-used buffer len %u leaving %u "
			     "avail on encap_seq %llu",
			     __FUNCTION__, blen,
			     satd->tfs_encap.q_packet_avail,
			     vnet_buffer_iptfs_esp_seq (b0));
	  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
	  return true;
	}

      /* We guarantee we don't queue these for the don't fragment case */
      ASSERT (!satd->tfs_df);

      /* We should never have any avail sine we have some remaining */
      ASSERT (!avail);

      /*
       * This buffer is larger than our MTU size we need to fragment it
       * into new buffer. We will allocate header buffers for each
       * required TFS packets, each of these header buffers will have
       * another indirect chained buffer which points back to the chunk
       * of data inside this buffer. We probably want to also look into
       * performance when copying small final chunks into the last header
       * buffer directly rather than chaining.
       */

      data_off = b0->current_data + b0->current_length;

      iptfs_pkt_debug_s (dbg,
			 "%s: Re-used buffer longer than our MTU (blen %u mtu "
			 "%u remaining %u) encap_seq %llu",
			 __FUNCTION__, blen, mtu, remaining,
			 vnet_buffer_iptfs_esp_seq (b0));

      /*
       * data_off - offset from b0->data to remaining data.
       * remaining - size of data remaining to send.
       *
       * we've allocated enough buffers to do this, and validated we can
       * queue them.
       */
    }
  else
    {
      /*---------------------------------------*/
      /* Add to an existing in-progress packet */
      /*---------------------------------------*/

      /* We must have in progress packet here b/c there's some available
       */
      iptfs_assert (satd->tfs_encap.infirst != ~0u);
      iptfs_assert (satd->tfs_encap.q_packet_avail == avail);
      iptfs_assert (satd->tfs_encap.q_packet_avail >=
		    IPTFS_ENCAP_MIN_AVAIL_SPACE);

      vlib_buffer_t *clastb;
      vlib_buffer_t *cb = iptfs_encap_get_in_progress (vm, satd, &clastb);
      ASSERT ((cb->flags & VLIB_BUFFER_NEXT_PRESENT) == 0 ||
	      cb->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
      u16 cblen = vlib_buffer_length_in_chain (vm, cb);

      iptfs_pkt_debug_s (dbg,
			 "%s: Have in-progress buffer mtu %u cl %u avail %u "
			 "remaining %u) encap_seq %llu",
			 __FUNCTION__, mtu, cblen, avail, remaining,
			 vnet_buffer_iptfs_esp_seq (cb));

      /* This is some debug */
      if (PREDICT_FALSE (cblen >= mtu))
	{
	  iptfs_log ("%s: Have in-progress buffer mtu %u cl %u avail %u "
		     "remaining %u) encap_seq %llu",
		     __FUNCTION__, mtu, cblen, avail, remaining,
		     vnet_buffer_iptfs_esp_seq (cb));
	}
      ASSERT (cblen < mtu);
      ASSERT (mtu - cblen == avail);

      u16 addlen = clib_min (remaining, avail);

#ifdef IPTFS_DEBUG
      if (CLIB_ASSERT_ENABLE)
	{
	  if (cb == clastb)
	    ASSERT (cb->total_length_not_including_first_buffer == 0);
	  else
	    {
	      ASSERT (cb->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
	      ASSERT (cb->total_length_not_including_first_buffer +
			  cb->current_length ==
		      cblen);
	    }
	}
#endif

      /*
       * PRE MODIFY: we do anything make sure we can get any extra
       * buffers and also that we will be able to queue them.
       */

      remaining -= addlen;
      ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
      if (!iptfs_encap_validate_queue_and_buffers (vm, sa_index, satd,
						   remaining, payspace, true))
	{
	  iptfs_debug ("%s: FAIL: chain-start-buffer len %u "
		       "chain-start-tot-len-nifb "
		       "%u avail %u copylen %u remaining %u Q ring avail %u",
		       __FUNCTION__, cb->current_length,
		       cb->total_length_not_including_first_buffer, avail,
		       addlen, remaining,
		       iptfs_bufq_avail (&satd->tfs_encap.outq));
	  goto fail;
	}

      ASSERT (lastb == b0); /* XXX not handling ingress chains */

      /* Add to chain! */
      clastb->next_buffer = bi0;
      if ((cb->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	{
	  cb->total_length_not_including_first_buffer = addlen;
	  cb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	}
      else
	{
	  ASSERT (cb->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
	  cb->total_length_not_including_first_buffer += addlen;
	}
      clastb->flags |= VLIB_BUFFER_NEXT_PRESENT;
      clastb = satd->tfs_encap.inlastb = lastb;

      /* Trim b0 to what we can use */
      /* XXX: Not handling chained buffers here */
      b0->current_length = addlen;

      // satd->tfs_encap.inccount += chaincount;
      avail -= addlen;

      iptfs_pkt_debug_s (dbg,
			 "%s: Appended %u to queued leaving %u avail "
			 "(remain %u to copy)",
			 __FUNCTION__, addlen, avail, remaining);

      /* Track the amount of queue data this packet represents include
       * header
       */
      vnet_buffer (cb)->ipsec.tfs_actual_data += addlen;
      cb->flags |= (b0flags & VLIB_BUFFER_IS_TRACED);

      if (remaining)
	{
	  /*
	   * This situation could be optimized we are fetching the buffer
	   * pointer, doing ASSERTs on some values and returning the pointer
	   * from iptfs_encap_add_empty_buffer. Then we are storing the buffer
	   * pointer in inlastb below, and then we will immediately reset that
	   * value when we queue the packet in iptfs_encap_fixup_buf_and_avail
	   * where we only use the buffer pointer to see if we were chained.
	   * Basically we could inline the known path
	   * iptfs_encap_fixup_buf_and_avail is going to take here after
	   * setting next_buffer and the flag in the current lastb.
	   */

	  /* We need to add a buffer to the end of this chain as we will
	     continue to use the packet data indirectly. */
	  lastb =
	      iptfs_encap_add_empty_buffer (vm, lastb,
					    vec_pop (satd->tfs_encap.buffers));

	  /* We are already chained, total length is valid, and we aren't
	     adding any length with an empty buffer so nothing to be done on
	     that front. */

	  /* Update the lastb in the inprogress */
	  clastb = satd->tfs_encap.inlastb = lastb;

	  /* The packet must queue with an empty buffer appended */
	  ASSERT (avail == 0);
	}

      if (!iptfs_encap_fixup_buf_and_avail (vm, satd, avail, false))
	{
	  /* we've verified we have space so this should never happen */
	  ASSERT (0);
	}

      if (remaining == 0)
	{
	  iptfs_pkt_debug_s (dbg,
			     "%s: packet len %u fit in existing queued iptfs "
			     "packet leaving %u space",
			     __FUNCTION__, blen,
			     satd->tfs_encap.q_packet_avail);
	  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
	  return true;
	}

      /*
       * We have data remaining, we have allocated header buffers for all
       * the required packets, plus a buffer per header for indirectly
       * pointing at the data
       */
      data_off = b0->current_data + b0->current_length;
    }
  ASSERT (!satd->tfs_encap.q_packet_avail);

  /*-------------------------*/
  /* We have some left over! */
  /*-------------------------*/

  /*
   * We have queued the current in progress chain, we have a pointer into
   * the current buffers 'data' and the 'remaining' size of this 'data'.
   * We have allocated 2 buffers for for each required chunk, 1 for the
   * header and 1 for chaining with indirect pointers into data. These
   * indirect buffers will reference b0
   */

  ASSERT (satd->tfs_encap.infirst == ~0u);
  ASSERT (satd->tfs_encap.inlastb == NULL);
  // ASSERT (satd->tfs_encap.inccount == 0);
  ASSERT (remaining);
  ASSERT (vec_len (satd->tfs_encap.buffers));

  u32 *buffers = satd->tfs_encap.buffers;

  iptfs_pkt_debug_s (dbg,
		     "%s: alloc'd %u new buffers, remaining %u payspace %u "
		     "vec_len(buffers) %u",
		     __FUNCTION__, vec_len (buffers), remaining, payspace,
		     vec_len (satd->tfs_encap.buffers));

  /*
   * We have the buffers and queue space, fill them up.
   */

  u32 hlen = iptfs_sa_data_hdrlen (satd);
  u32 *bi = buffers;
  u32 *ebi = bi + vec_len (buffers);
  vlib_buffer_t *hdrbuf = NULL;
  u16 cblen = 0;
  while (bi < ebi)
    {
      vlib_buffer_t *indbuf;
      ASSERT (remaining);

      u32 hdri = *bi++;
      hdrbuf = iptfs_check_empty_buffer (vm, hdri, sa_index);

      ipsec_iptfs_basic_header_t *h = vlib_buffer_put_uninit (hdrbuf, hlen);
      clib_memset (h, 0, hlen);
      if (hlen == sizeof (ipsec_iptfs_cc_header_t))
	h->subtype = IPTFS_SUBTYPE_CC;
      h->block_offset = clib_host_to_net_u16 (remaining);

#ifdef IPTFS_DEBUG_CORRUPTION
      vnet_buffer_iptfs_esp_seq (hdrbuf) = satd->tfs_tx.encap_seq++;
#endif
      /*
       * If the remaining data fits in the cacheline of the header buffer
       * we already have then just copy it. We probably want to
       * experiment with multiple cache lines.
       */
      u16 addlen = clib_min (remaining, payspace);

      /* Track amount of queue data this packet represents excludes
       * header */
      vnet_buffer (hdrbuf)->ipsec.tfs_actual_data = addlen;
      hdrbuf->flags |= (b0flags & VLIB_BUFFER_IS_TRACED);

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0flags & VLIB_BUFFER_IS_TRACED)))
	iptfs_encap_trace_new_buffer (vm, node, hdrbuf, sa_index);

#ifdef IPTFS_ENCAP_COPY_AND_CHAIN
      if (remaining <= IPTFS_ENCAP_STRADDLE_COPY_OVER_INDRECT_SIZE (satd))
	{
	  ASSERT (addlen == remaining);
	  iptfs_assert (addlen == remaining);
	  clib_memcpy_fast (vlib_buffer_put_uninit (hdrbuf, addlen),
			    b0->data + data_off, addlen);
	  cblen = hdrbuf->current_length;

	  /* We ASSERT this case above to catch bugs */
	  if (CLIB_ASSERT_ENABLE)
	    hdrbuf->total_length_not_including_first_buffer = 0;

	  /* the last buffer is our in-progress buffer */
	  satd->tfs_encap.infirst = hdri;
	  satd->tfs_encap.inlastb = hdrbuf;
	  // satd->tfs_encap.inccount = 1;

	  iptfs_pkt_debug_s (dbg,
			     "%s: copied %u to unfinished header "
			     "buffer, leaving %u avail",
			     __FUNCTION__, addlen, mtu - cblen);

	  data_off += addlen;
	  remaining -= addlen;

	  /*
	   * XXX: Technically the user could set a small enough MTU, do
	   * something to fix this. We may want to allow this threshold
	   * to be settable.
	   */
	  iptfs_assert (cblen != mtu); /* We should never be finished at this
					  point */
	  iptfs_assert (bi == vec_end (buffers));

	  iptfs_inc_x_counter (IPTFS_CNT_ENCAP_STRADDLE_COPY, thread_index,
			       sa_index, 1);
	  break;
	}
#endif

      u32 indbi = *bi++;
      indbuf =
	  iptfs_init_chained_indirect_buffer (vm, indbi, b0, data_off, addlen);

      iptfs_pkt_debug_s (
	  dbg,
	  "%s: add indirect 0x%x to new header (encap_seq %llu), "
	  "indbuf->ref_count %d imb->refcount %d b0->ref_count "
	  "%d b0mb->refcount %d",
	  __FUNCTION__, indbi, vnet_buffer_iptfs_esp_seq (hdrbuf),
	  indbuf->ref_count, vlib_buffer_get_mbuf_refcount (vm, indbuf),
	  b0->ref_count, vlib_buffer_get_mbuf_refcount (vm, b0));

      /* Add to chain! */
      hdrbuf->next_buffer = indbi;
      hdrbuf->total_length_not_including_first_buffer = addlen;
      hdrbuf->flags |=
	  VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID;

      data_off += addlen;
      remaining -= addlen;

      /* if we have remaining then queue this buffer */
      if (remaining)
	{
	  /* We need to also attach an empty buffer for the ESP footer */
	  iptfs_encap_add_empty_buffer (vm, indbuf, *bi++);
	  if (!iptfs_bufq_enqueue (&satd->tfs_encap.outq, hdri, addlen))
	    ASSERT (0 /* Never */);

	  iptfs_pkt_debug_s (dbg,
			     "%s: added %u to new queued indirect buffer "
			     "chain %u remaining",
			     __FUNCTION__, addlen, remaining);
	  /* We should never end the loop after this with some remaining */
	  iptfs_assert (bi != ebi);
	}
      else
	{
	  /* Get the length of this last buffer chain */
	  cblen = hdrbuf->current_length +
		  hdrbuf->total_length_not_including_first_buffer;

	  /* If this packet is done, we need to attach an empty buffer for the
	   * ESP footer */
	  if (cblen == mtu)
	    indbuf = iptfs_encap_add_empty_buffer (vm, indbuf, *bi++);

	  /* the last buffer is our in-progress buffer */
	  satd->tfs_encap.infirst = hdri;
	  satd->tfs_encap.inlastb = indbuf;
	  // satd->tfs_encap.inccount = 2;
	  iptfs_pkt_debug_s (dbg,
			     "%s: added %u to new unfinished buffer chain, "
			     "leaving %u avail",
			     __FUNCTION__, addlen, mtu - cblen);
	  /* We need to be done with our buffers here */
	  iptfs_assert (bi == vec_end (buffers));
	}
    }

  if (bi != vec_end (buffers))
    iptfs_log ("%s: didn't consume all buffers, leftover %d", __FUNCTION__,
	       vec_end (buffers) - bi);
  iptfs_assert (bi == vec_end (buffers));

  /* We're done with our scratch */
  vec_reset_length (satd->tfs_encap.buffers);

#ifdef IPTFS_DEBUG
  if (CLIB_ASSERT_ENABLE)
    {
      if ((hdrbuf->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	ASSERT (hdrbuf->current_length == cblen);
      else
	ASSERT (hdrbuf->current_length +
		    hdrbuf->total_length_not_including_first_buffer ==
		cblen);
    }
#endif

  ASSERT (!remaining);
  if (!iptfs_encap_fixup_buf_and_avail (vm, satd, mtu - cblen, false))
    {
      /* we've verified we have space so this should never happen */
      ASSERT (0);
    }
  /* We could be leavig here with some avail. */

  iptfs_pkt_debug_s (dbg, "%s: Leaving with %u available on queue.",
		     __FUNCTION__, satd->tfs_encap.q_packet_avail);

  return true;

fail:
  /* Also copied from the copied code verbatim */
  b0->error = node->errors[IPTFS_ENCAP_ERROR_NO_BUF];

#ifdef IPTFS_DEBUG_CORRUPTION
  iptfs_dump_debug_strings (false);
  /* XXX corruption debug remove me */
  ASSERT (0);
#endif
  iptfs_debug ("%s: FAIL: Q:{ring slots avail %u of %u, bytes avail %u of %u "
	       "next slot %u n_enq: %u} zbuffers avail %u, pkt avail %u, data "
	       "remaining: %u payspace %u",
	       __FUNCTION__, iptfs_bufq_avail (&satd->tfs_encap.outq),
	       iptfs_bufq_capacity (&satd->tfs_encap.outq),
	       satd->tfs_encap.limit.max_size - satd->tfs_encap.limit.size,
	       satd->tfs_encap.limit.max_size,
	       clib_ring_header (satd->tfs_encap.outq.q)->next,
	       clib_ring_header (satd->tfs_encap.outq.q)->n_enq,
	       iptfs_zpool_get_avail (satd->tfs_encap.zpool),
	       satd->tfs_encap.q_packet_avail, remaining, payspace);

  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);

  return false;
}

/*
 * Add packet to queue, if fails buffer queue size is unchanged
 */
static inline bool
iptfs_encap_add_packet_copy (vlib_main_t *vm, vlib_node_runtime_t *node,
			     u32 thread_index, u32 sa_index,
			     iptfs_sa_data_t *satd, u32 bi0, vlib_buffer_t *b0,
			     u32 **freeb, IPTFS_DBG_ARG (u8 **dbg))
{
  /*
   * Queue is locked. Grab top most buffer and add this buffer to it.
   * 1A) If queue is empty, own this buffer and use it.
   * 1B) else queue has a packet, use that packet and copy/reference this
   * buffer inside it. If this packet doesn't fit grab the all pad buffer
   * and add the rest of this packet to that.
   */
  iptfs_pkt_debug_s (dbg, "%s Entered: in thread %u", __FUNCTION__,
		     thread_index);

  iptfs_assert (thread_index == satd->tfs_encap.encap_thread_index);

  u16 mtu = satd->tfs_encap.tfs_ipsec_payload_size;
  u32 b0flags = b0->flags;
  bool reused = false;

  /*
   * If nothing usable queued, re-use this buffer and queue it.
   */
  u32 blen = vlib_buffer_length_in_chain (vm, b0);
  u8 *data = vlib_buffer_get_current (b0);
  u16 avail = satd->tfs_encap.q_packet_avail;
  u16 remaining = blen;

  /*
   * Handle the case where we need to first close off an in-progress
   */
  u32 first = satd->tfs_encap.infirst;
  if (first != ~0u && PREDICT_FALSE (satd->tfs_df && remaining > avail))
    {
#ifdef IPTFS_DEBUG
#ifdef IPTFS_DEBUG_CORRUPTION
      vlib_buffer_t *cb = iptfs_encap_get_in_progress (vm, satd, NULL);

      /* If we are not fragmenting, and remaining > avail, close the
	 current buffer and start a new one */
      iptfs_pkt_debug_s (
	  dbg,
	  "%s: Have too small in-progress buffer for DF case mtu "
	  "%u cl %u avail %u remaining %u queueing encap_seq %llu",
	  __FUNCTION__, mtu, vlib_buffer_length_in_chain (vm, cb), avail,
	  remaining, satd->tfs_tx.encap_seq);
#endif
#endif
      /* move current packet to the queue */
      if (!iptfs_encap_fixup_buf_and_avail (vm, satd, avail, true))
	*(*freeb)++ = first;
      avail = 0;
    }

  /* We should never have an in-progress packet with nothing available in
   * it
   */
  ASSERT (satd->tfs_encap.infirst == ~0u || avail);

  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);

  /* We never leave it set < IPTFS_ENCAP_MIN_AVAIL_SPACE and not 0 */
  ASSERT (avail >= IPTFS_ENCAP_MIN_AVAIL_SPACE ||
	  satd->tfs_encap.q_packet_avail == 0);

  const u16 payspace = mtu - iptfs_sa_data_hdrlen (satd);
  if (!avail)
    {
      /*--------------------------------------*/
      /* Start a new packet using user packet */
      /*--------------------------------------*/

      ASSERT (satd->tfs_encap.infirst == ~0u);
      ASSERT (satd->tfs_encap.inlastb == NULL);
      // ASSERT (satd->tfs_encap.inccount == 0);

      /* Fixup buffer for our use and queue */
      blen += iptfs_encap_reuse_buffer (b0, satd);
      reused = true;

      if (blen < mtu)
	{
	  avail = mtu - blen;
	  remaining = 0;

	  /* Save this as in-progress packet */
	  satd->tfs_encap.infirst = bi0;
	  satd->tfs_encap.inlastb = b0;
	  // satd->tfs_encap.inccount = 1;
	}
      else
	{
	  avail = 0;
	  remaining = blen - mtu;

	  /* Verify we have enough space to finish sending the packet */
	  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
	  if (!iptfs_encap_validate_queue_and_buffers (vm, sa_index, satd,
						       remaining, payspace,
						       false))
	    {
	      iptfs_debug ("%s: FAIL: b0cl %u blen %u mtu %u Q ring avail %u",
			   __FUNCTION__, b0->current_length, blen, mtu,
			   iptfs_bufq_avail (&satd->tfs_encap.outq));
	      goto fail;
	    }

	  /* shrink buffer to MTU size */
	  b0->current_length -= remaining;
	  ASSERT (b0->current_length == mtu);
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	*(u32 *)vlib_add_trace (vm, node, b0, sizeof (u32)) = sa_index;

      /* Track the amount of queue data this packet represents */
      vnet_buffer (b0)->ipsec.tfs_actual_data =
	  b0->current_length - iptfs_sa_data_hdrlen (satd);

      satd->tfs_encap.q_packet_avail = avail;

      /* Queue the full packet */
      if (!avail &&
	  !iptfs_bufq_enqueue (&satd->tfs_encap.outq, bi0,
			       vnet_buffer (b0)->ipsec.tfs_actual_data))
	{
	  clib_warning ("%s: failed to queue buffer %u", __FUNCTION__, bi0);
	  ASSERT (0); /* we verified this would succeed above */
	}

      if (!remaining)
	{
	  iptfs_pkt_debug_s (dbg,
			     "%s: Re-used buffer len %u leaving %u "
			     "avail on encap_seq %llu",
			     __FUNCTION__, blen,
			     satd->tfs_encap.q_packet_avail,
			     vnet_buffer_iptfs_esp_seq (b0));
	  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
	  return true;
	}

      /* We guarantee we don't queue these for the don't fragment case */
      ASSERT (!satd->tfs_df);

      /* We should never have any avail sine we have some remaining */
      ASSERT (!avail);

      iptfs_pkt_debug_s (dbg,
			 "%s: Re-used buffer longer than our MTU (blen %u mtu "
			 "%u remaining %u) encap_seq %llu",
			 __FUNCTION__, blen, mtu, remaining,
			 vnet_buffer_iptfs_esp_seq (b0));

      data = vlib_buffer_get_tail (b0);
    }
  else
    {
      /*---------------------------------------*/
      /* Add to an existing in-progress packet */
      /*---------------------------------------*/

      /* We must have in progress packet here b/c there's some available
       */
      ASSERT (satd->tfs_encap.infirst != ~0u);
      ASSERT (satd->tfs_encap.q_packet_avail == avail);
      ASSERT (satd->tfs_encap.q_packet_avail >= IPTFS_ENCAP_MIN_AVAIL_SPACE);

      vlib_buffer_t *clastb;
      vlib_buffer_t *cb = iptfs_encap_get_in_progress (vm, satd, &clastb);

      ASSERT (cb == clastb);

      iptfs_pkt_debug_s (dbg,
			 "%s: Have in-progress buffer mtu %u cl %u avail %u "
			 "remaining %u) encap_seq %llu",
			 __FUNCTION__, mtu, cb->current_length, avail,
			 remaining, vnet_buffer_iptfs_esp_seq (cb));
      ASSERT (cb);
      ASSERT (cb->current_length < mtu);
      ASSERT (mtu - cb->current_length == avail);

      u16 copylen = clib_min (remaining, avail);

      /*
       * PRE MODIFY: we do anything make sure we can get any extra
       * buffers and also that we will be able to queue them.
       */
      remaining -= copylen;
      ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
      if (!iptfs_encap_validate_queue_and_buffers (vm, sa_index, satd,
						   remaining, payspace, false))
	{
	  iptfs_debug ("%s: FAIL: cbcl %u avail %u copylen %u", __FUNCTION__,
		       cb->current_length, avail, copylen);
	  goto fail;
	}

      clib_memcpy_fast (vlib_buffer_get_tail (cb), data, copylen);
      cb->current_length += copylen;
      data += copylen;
      avail -= copylen;

      iptfs_pkt_debug_s (dbg,
			 "%s: Appended %u to queued leaving %u avail "
			 "(remain %u to copy)",
			 __FUNCTION__, copylen, avail, remaining);

      /* Track the amount of queue data this packet represents include
       * header
       */
      vnet_buffer (cb)->ipsec.tfs_actual_data += copylen;
      cb->flags |= (b0flags & VLIB_BUFFER_IS_TRACED);

      if (!iptfs_encap_fixup_buf_and_avail (vm, satd, avail, false))
	{
	  /* we've verified we have space so this should never happen */
	  ASSERT (0);
	}

      if (remaining == 0)
	{
	  iptfs_pkt_debug_s (
	      dbg,
	      "%s: packet len remaining %u fit in existing queued iptfs "
	      "packet leaving %u space",
	      __FUNCTION__, copylen, satd->tfs_encap.q_packet_avail);

	  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
	  /* Free the user packet as we've copied all of it */
	  *(*freeb)++ = bi0;
	  return true;
	}

      ASSERT (!satd->tfs_encap.q_packet_avail);
    }

  /*-------------------------*/
  /* We have some left over! */
  /*-------------------------*/

  ASSERT (satd->tfs_encap.infirst == ~0u);
  ASSERT (satd->tfs_encap.inlastb == NULL);
  // ASSERT (satd->tfs_encap.inccount == 0);
  ASSERT (remaining);
  ASSERT (vec_len (satd->tfs_encap.buffers));

  u32 *buffers = satd->tfs_encap.buffers;

  iptfs_pkt_debug_s (dbg,
		     "%s: alloc'd %u new buffers, remaining %u payspace %u "
		     "vec_len(buffers) %u",
		     __FUNCTION__, vec_len (buffers), remaining, payspace,
		     vec_len (satd->tfs_encap.buffers));

  /*
   * We have the buffers and queue space, fill them up.
   */

  u32 *bi;
  vlib_buffer_t *newbuf = NULL;
  u16 hlen = iptfs_sa_data_hdrlen (satd);
  vec_foreach (bi, buffers)
  {
    newbuf = iptfs_check_empty_buffer (vm, *bi, sa_index);

    u16 copylen = clib_min (remaining, payspace);
    ipsec_iptfs_basic_header_t *h = vlib_buffer_put_uninit (newbuf, hlen);
    clib_memset (h, 0, hlen);
    if (hlen == sizeof (ipsec_iptfs_cc_header_t))
      h->subtype = IPTFS_SUBTYPE_CC;
    h->block_offset = clib_host_to_net_u16 (remaining);

    clib_memcpy_fast ((u8 *)h + hlen, data, copylen);
    newbuf->current_length += copylen;

    /* Track the amount of queue data this packet represents excludes
     * header
     */
    vnet_buffer (newbuf)->ipsec.tfs_actual_data = copylen;
    newbuf->flags |= (b0flags & VLIB_BUFFER_IS_TRACED);
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		       (b0flags & VLIB_BUFFER_IS_TRACED)))
      iptfs_encap_trace_new_buffer (vm, node, newbuf, sa_index);

    data += copylen;
    remaining -= copylen;

    /* if we have remaining then queue this buffer */
    if (remaining)
      {
	if (!iptfs_bufq_enqueue (&satd->tfs_encap.outq, *bi, copylen))
	  ASSERT (0 /* Never */);
      }
    else
      {
	/* the last buffer is our in-progress buffer */
	satd->tfs_encap.infirst = *bi;
	satd->tfs_encap.inlastb = newbuf;
	// satd->tfs_encap.inccount = 1;
      }

    iptfs_pkt_debug_s (
	dbg, "%s: copied %u to new queued buffer (cl: %u) %u remaining.",
	__FUNCTION__, copylen, newbuf->current_length, remaining);
  }

  /* We're done with our scratch */
  vec_reset_length (satd->tfs_encap.buffers);

  ASSERT (!remaining);
  if (!iptfs_encap_fixup_buf_and_avail (vm, satd, mtu - newbuf->current_length,
					false))
    {
      /* we've verified we have space so this should never happen */
      ASSERT (0);
    }

  iptfs_pkt_debug_s (dbg, "%s: Leaving with %u available on queue.",
		     __FUNCTION__, satd->tfs_encap.q_packet_avail);

  /* Free the user packet unless we re-used it */
  if (!reused)
    *(*freeb)++ = bi0;

  return true;

fail:
  b0->error = node->errors[IPTFS_ENCAP_ERROR_NO_BUF];

  iptfs_debug ("%s: FAIL: Q:{ring slots avail %u of %u, bytes avail %u of %u "
	       "next slot %u n_enq: %u} zbuffers avail %u, pkt avail %u, data "
	       "remaining: %u payspace %u",
	       __FUNCTION__, iptfs_bufq_avail (&satd->tfs_encap.outq),
	       iptfs_bufq_capacity (&satd->tfs_encap.outq),
	       satd->tfs_encap.limit.max_size - satd->tfs_encap.limit.size,
	       satd->tfs_encap.limit.max_size,
	       clib_ring_header (satd->tfs_encap.outq.q)->next,
	       clib_ring_header (satd->tfs_encap.outq.q)->n_enq,
	       iptfs_zpool_get_avail (satd->tfs_encap.zpool),
	       satd->tfs_encap.q_packet_avail, remaining, payspace);

  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);

  return false;
}

/*
 * Send all encap-only queued packets
 */
static inline void
iptfs_encap_only_send (vlib_main_t *vm, vlib_node_runtime_t *node,
		       u32 sa_index)
{
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

  /*
   * If we have an inprogress packet, queue it
   */
  u32 first = satd->tfs_encap.infirst;
  if (first != ~0u)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, first);
      u32 size = vnet_buffer (b0)->ipsec.tfs_actual_data;
      satd->tfs_encap.infirst = ~0u;
      satd->tfs_encap.inlastb = NULL;
      satd->tfs_encap.q_packet_avail = 0;
      bool ok = iptfs_bufq_enqueue (&satd->tfs_encap.outq, first, size);
      iptfs_assert (ok);
    }

  u32 n_avail = iptfs_bufq_n_enq (&satd->tfs_encap.outq);
  if (!n_avail)
    return;

  u32 next_index;
  if (PREDICT_FALSE (satd->tfs_ipv6))
    next_index = IPTFS_ENCAP_NEXT_ESP6_ENCRYPT;
  else
    next_index = IPTFS_ENCAP_NEXT_ESP4_ENCRYPT;

  u32 sizes[VLIB_FRAME_SIZE];
  u32 *to = NULL;
  u32 *eto = NULL;

  if (satd->tfs_encap.output_thread_index != vlib_get_thread_index ())
    {
      u16 ht[VLIB_FRAME_SIZE];
      u32 t[VLIB_FRAME_SIZE];
      u32 maxthread = clib_min (n_avail, VLIB_FRAME_SIZE);

      for (uint i = 0; i < maxthread; i++)
	ht[i] = satd->tfs_encap.output_thread_index;

      u32 fqi;
      if (PREDICT_FALSE (satd->tfs_ipv6))
	fqi = ipsec_iptfs_main.encap6_only_frame_queue;
      else
	fqi = ipsec_iptfs_main.encap4_only_frame_queue;

      while (n_avail)
	{
	  u32 count =
	      iptfs_bufq_ndequeue (&satd->tfs_encap.outq, t, sizes,
				   clib_min (n_avail, VLIB_FRAME_SIZE));
	  (void)vlib_buffer_enqueue_to_thread (vm, fqi, t, ht, count, 0);

	  /* size accounting -- really not needed */
	  u32 total_actual_data = 0;
	  for (uint i = 0; i < count; i++)
	    total_actual_data += sizes[i];
	  ASSERT (satd->tfs_encap.limit.size >= total_actual_data);
	  satd->tfs_encap.limit.size -= total_actual_data;

	  n_avail -= count;
	}
    }
  else
    while (n_avail)
      {
	vlib_get_next_frame_p (vm, node, next_index, to, eto);
	u32 count = iptfs_bufq_ndequeue (&satd->tfs_encap.outq, to, sizes,
					 clib_min (n_avail, eto - to));
	to += count;
	vlib_put_next_frame (vm, node, next_index, eto - to);

	/* size accounting -- really not needed */
	u32 total_actual_data = 0;
	for (uint i = 0; i < count; i++)
	  total_actual_data += sizes[i];
	ASSERT (satd->tfs_encap.limit.size >= total_actual_data);
	satd->tfs_encap.limit.size -= total_actual_data;

	n_avail -= count;
      }
}

/*
 * Enqueue packets for paced transmission
 */
static inline uword
iptfs_encap_enq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vlib_frame_t *frame, bool is_feature,
			     bool maybe_handoff)
{
  u32 thread_index = vlib_get_thread_index ();
  vlib_buffer_t *_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **bufs = _bufs;
  vlib_buffer_t **b = bufs, **eb = bufs + frame->n_vectors;
  u32 freebufs[VLIB_FRAME_SIZE];
  u32 *freeb = freebufs;
  iptfs_sa_data_t *satd = 0;
  u32 *from;
  u32 newqsz;
  u32 sa_index = ~0u;
  u16 max_payload = 0;
  u8 df = false;

  IPTFS_DBG_ARG (u8 * *dbg) = iptfs_next_debug_string ();

  iptfs_pkt_debug_s (dbg, "%s Entered: in thread %u", __FUNCTION__,
		     thread_index);

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);

#if IPTFS_ENABLE_ENCAP_MULTITHREAD
  u32 handoff[VLIB_FRAME_SIZE], *h = handoff;
  u16 threads[VLIB_FRAME_SIZE], *ht = threads;
  /*
   * If we have multiple encap threads then handoff the ones for another thread
   * immediately so that they can be processed in parallel.
   */
  if (maybe_handoff)
    {
      u32 this_thread_index = vlib_get_thread_index ();
      u32 htcount = 0, bufcount = 0;
      while (b < eb)
	{
	  FOREACH_PREFETCH_WITH_DATA (b, eb, IPTFS_N_PREFETCH_ENCAP_HANDOFF,
				      STORE)
	  {
	    vlib_buffer_t *b0 = *b;
	    u32 bi0 = from[b - bufs];
	    u32 _sa_index;
	    if (!is_feature)
	      _sa_index = vnet_buffer (b0)->ipsec.sad_index;
	    else
	      {
		u32 _next;
		_sa_index =
		    *(u32 *)vnet_feature_next_with_data (&_next, b0,
							 sizeof (sa_index));
		/* Save the sa index in the buffer */
		vnet_buffer (b0)->ipsec.sad_index = _sa_index;
	      }
	    if (_sa_index != sa_index)
	      {
		sa_index = _sa_index;
		satd = iptfs_get_sa_data (sa_index);
		thread_index = satd->tfs_encap.encap_thread_index;
	      }

	    if (thread_index == this_thread_index)
	      {
		/* Compress the buffers and from array */
		bufs[bufcount] = b0;
		from[bufcount] = bi0;
		bufcount++;
	      }
	    else
	      {
		*h++ = bi0;
		*ht++ = thread_index;
		htcount++;
	      }
	  }
	  END_FOREACH_PREFETCH;
	}

      if (htcount)
	{
	  /* handoff buffers */
	  u32 n_enq = vlib_buffer_enqueue_to_thread (
	      vm, ipsec_iptfs_main.encap_frame_queue, handoff, threads,
	      htcount, 0);
	  iptfs_assert (n_enq == htcount);

	  if (!bufcount)
	    {
	      ASSERT (htcount == frame->n_vectors);
	      return frame->n_vectors;
	    }
	}
      /* Reset the buffers pointers */
      b = bufs;
      eb = b + bufcount;
    }
#else
#endif

  /*
   * There are 2 destinations, 1 our queue, 2 error-drop. So next-index
   * will always be error-drop. We expect the error-drop frame to have
   * plenty of space, if it doesn't we need to stop checking it so much
   * as it is the the error path, and our queue is the predicted path.
   */

  u32 *to[IPTFS_ENCAP_N_NEXT] = {};
  u32 *eto[IPTFS_ENCAP_N_NEXT] = {};

  while (b < eb)
    {
      // XXX we only store in the data if we re-use the buffer, for small
      // packets this will not be that often, so STORE prefetch is maybe
      // wrong.
      // XXX really need to analyze this better.
      FOREACH_PREFETCH_WITH_DATA (b, eb, IPTFS_N_PREFETCH_ENCAP, STORE)
      {
	vlib_buffer_t *b0 = *b;
	u32 bi0 = from[b - bufs];
	u8 *data = vlib_buffer_get_current (b0);
	/* XXX do we need to check for 1 byte length available here? */
	ASSERT (b0->current_length);
	u8 ptype = *data & 0xF0;

	iptfs_pkt_debug_s (dbg,
			   "%s: Packet for IPTFS encap: current_data %u "
			   "current_length %u *data %u",
			   __FUNCTION__, b[0]->current_data,
			   b[0]->current_length, ptype);

	if (PREDICT_FALSE (ptype != 0x40 && ptype != 0x60))
	  {
	    iptfs_pkt_debug_s (dbg,
			       "%s: Unrecognized packet %u for IPTFS encap",
			       __FUNCTION__, *data);
	    b0->error = node->errors[IPTFS_ENCAP_ERROR_UNKNONW_TYPE];
	    goto dropit;
	  }

	u32 _sa_index;
	if (!is_feature)
	  _sa_index = vnet_buffer (b0)->ipsec.sad_index;
#if IPTFS_ENABLE_ENCAP_MULTITHREAD
	/* We have set the index in the handoff check above */
	else if (maybe_handoff)
	  _sa_index = vnet_buffer (b0)->ipsec.sad_index;
#endif
	else
	  {
	    u32 _next;
	    _sa_index =
		*(u32 *)vnet_feature_next_with_data (&_next, b0,
						     sizeof (sa_index));
	  }
	if (_sa_index != sa_index)
	  {
	    sa_index = _sa_index;
	    satd = iptfs_get_sa_data (sa_index);
	    thread_index = satd->tfs_encap.encap_thread_index;
	    max_payload = satd->tfs_encap.tfs_ipsec_payload_size -
			  iptfs_sa_data_hdrlen (satd);
	    df = satd->tfs_df;
	    iptfs_prefetch_x_counter (IPTFS_CNT_ENCAP_STRADDLE_COPY,
				      thread_index, sa_index);
	    iptfs_prefetch_pcounter (IPTFS_PCNT_ENCAP_RX, thread_index,
				     sa_index);
	    iptfs_prefetch_pcounter (IPTFS_PCNT_ENCAP_TX, thread_index,
				     sa_index);
	  }

	/* XXX we want to know if this is the case */
	ASSERT ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);

	u16 blen = iptfs_encap_buflen_fixup (vm, b0);
	iptfs_inc_pcounter (IPTFS_PCNT_ENCAP_RX, thread_index, sa_index, 1,
			    blen);

	if (PREDICT_FALSE ((blen == 0)))
	  {
	    b0->error = node->errors[IPTFS_ENCAP_ERROR_BAD_LEN];
	    goto dropit;
	  }

	if (PREDICT_FALSE ((blen > max_payload && df)))
	  {
	    /* Too large for our MTU send an ICMP or DROP */
	    const u32 ni =
		iptfs_icmp_unreach (vm, node, b0, max_payload, data);
	    vlib_put_get_next_frame_a (vm, node, ni, to, eto);
	    *to[ni]++ = bi0;
	  }

	else if ((newqsz = iptfs_bufq_check_limit (
		      &satd->tfs_encap.outq, &satd->tfs_encap.limit, blen)))
	  {
	    /*
	     * XXX design choice.
	     *
	     * NOTE: this currently allows smaller packets to get through
	     * even after we have dropped larger ones prior. This will
	     * cause out-of-order delivery which is bad; however, this
	     * only matters for dont-fragment case. Fix this eventually.
	     */

	    bool success;
	    if (satd->tfs_encap_chaining)
	      success =
		  iptfs_encap_add_packet (vm, node, thread_index, sa_index,
					  satd, bi0, b0, &freeb, dbg);
	    else
	      success = iptfs_encap_add_packet_copy (vm, node, thread_index,
						     sa_index, satd, bi0, b0,
						     &freeb, dbg);
	    if (success)
	      {
		iptfs_inc_pcounter (IPTFS_PCNT_ENCAP_TX, thread_index,
				    sa_index, 1, blen);
		satd->tfs_encap.limit.size = newqsz;
	      }

	    /*
	     * XXX This code counts on there being only 1 worker thread
	     * handling encap for this SA. If multiple rx workers exist for
	     * an SA then we need to create an input queue that we can
	     * serialize on. This would be the case if a device input is
	     * being taken from multiple worker threads.
	     */

	    if (!success)
	      goto dropit;

	    ELOG_TYPE_DECLARE (encap_enq) = {
		.format = "encap-enq sa_index %d newqsz %d max %d hard %d",
		.format_args = "i4i4i4i4",
	    };
	    u32 *esd = IPTFS_ELOG_THREAD (encap_enq, thread_index);
	    esd[0] = sa_index;
	    esd[1] = newqsz;
	    esd[2] = satd->tfs_encap.limit.max_size;
	    esd[3] = satd->tfs_encap.limit.hard_max_size;

	    /* We've added trace data in add_packet if need be */
	    goto notrace;
	  }
	else
	  {
	    u32 *esd;
	    ELOG_TYPE_DECLARE (encap_queue_full) = {
		.format =
		    "encap-queue-full sa_index %d size %d max %d hard %d",
		.format_args = "i4i4i4i4",
	    };
	    // esd = IPTFS_ELOG_THREAD (encap_queue_full, thread_index);
	    esd = IPTFS_ELOGP (&encap_queue_full, &satd->tfs_error_track);
	    esd[0] = sa_index;
	    esd[1] = satd->tfs_encap.limit.size;
	    esd[2] = satd->tfs_encap.limit.max_size;
	    esd[3] = satd->tfs_encap.limit.hard_max_size;

	    iptfs_inc_counter (IPTFS_CNT_ENCAP_Q_FULL, thread_index, sa_index,
			       1);
	    if (false)
	      {
	      dropit:;
		ELOG_TYPE_DECLARE (encap_drop) = {
		    .format = "encap-drop sa_index %d",
		    .format_args = "i4",
		};
		// esd = IPTFS_ELOG_THREAD (encap_drop, thread_index);
		esd = IPTFS_ELOGP (&encap_drop, &satd->tfs_error_track);
		esd[0] = sa_index;
	      }

	    vlib_put_get_next_frame_a (vm, node, IPTFS_ENCAP_NEXT_DROP, to,
				       eto);
	    *to[IPTFS_ENCAP_NEXT_DROP]++ = bi0;
	  }
	if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			   (b0->flags & VLIB_BUFFER_IS_TRACED)))
	  *(u32 *)vlib_add_trace (vm, node, b0, sizeof (u32)) = sa_index;
      notrace:;
      }
      END_FOREACH_PREFETCH;
#if 0
      /*
       * This seems to actually cause things to run slower. The idea was that if
       * we were spening too much time in the encap we wouldn't be queuing
       * things in time to the output thread. Could revist this some other time.
       *
       * Need to cleanup the tracing that might happen in pacer routine using
       * the encap runtime node (the only use of the node passed in here).
       */
      {
	iptfs_thread_main_t *tm =
	    vec_elt_at_index (ipsec_iptfs_main.workers_main, thread_index);
	u32 active_index, *active_vector = tm->sa_active[IPTFS_POLLER_PACER];
	vec_foreach_index (active_index, active_vector)
	{
	  iptfs_pacer_sa_send (vm, node, active_vector[active_index], false);
	}
      }
#endif
    }

  /*
   * Walk our active encap-only and send all the packets immediately
   */
  iptfs_thread_main_t *tm =
      vec_elt_at_index (ipsec_iptfs_main.workers_main, thread_index);
  u32 active_index, *active_vector = tm->sa_active[IPTFS_POLLER_ENCAP_ONLY];
  vec_foreach_index (active_index, active_vector)
  {
    iptfs_encap_only_send (vm, node, active_vector[active_index]);
  }

  /* Put any next frames we've used */
  for (uint i = 0; i < IPTFS_ENCAP_N_NEXT; i++)
    if (to[i])
      vlib_put_next_frame (vm, node, i, eto[i] - to[i]);

  iptfs_pkt_debug_s (dbg, "%s Leaving %d", __FUNCTION__, frame->n_vectors);

  /* Free any buffers we need to */
  vlib_buffer_free (vm, freebufs, freeb - freebufs);

  return frame->n_vectors;
}

#if IPTFS_ENABLE_ENCAP_MULTITHREAD
VLIB_NODE_FN (iptfs_encap_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iptfs_pkt_debug ("%s: Entering", __FUNCTION__);

  return iptfs_encap_enq_node_inline (vm, node, frame, 0, false);
}

VLIB_REGISTER_NODE (iptfs_encap_handoff_node) = {
    .name = "iptfs-encap-handoff",
    .vector_size = sizeof (u32),
    .format_trace = format_iptfs_encap_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    /* XXX this is actually not true for any packets we drop/icmp error, they
       will be double counted */
    .flags = VLIB_NODE_FLAG_IS_OUTPUT | VLIB_NODE_FLAG_TRACE_SUPPORTED,

    .n_errors = ARRAY_LEN (iptfs_encap_error_strings),
    .error_strings = iptfs_encap_error_strings,

    .n_next_nodes = IPTFS_ENCAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
	{
#define _(s, n) [IPTFS_ENCAP_NEXT_##s] = n,
	    foreach_iptfs_encap_next
#undef _
	},
};
#endif

VLIB_NODE_FN (iptfs_encap_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iptfs_pkt_debug ("%s: Entering", __FUNCTION__);

  return iptfs_encap_enq_node_inline (vm, node, frame, 0,
				      IPTFS_ENABLE_ENCAP_MULTITHREAD);
}

VLIB_REGISTER_NODE (iptfs_encap_enq_node) = {
    .name = "iptfs-encap-enq",
    .vector_size = sizeof (u32),
    .format_trace = format_iptfs_encap_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    /* XXX this is actually not true for any packets we drop/icmp error, they
       will be double counted */
    .flags = VLIB_NODE_FLAG_IS_OUTPUT | VLIB_NODE_FLAG_TRACE_SUPPORTED,

    .n_errors = ARRAY_LEN (iptfs_encap_error_strings),
    .error_strings = iptfs_encap_error_strings,

    .n_next_nodes = IPTFS_ENCAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
	{
#define _(s, n) [IPTFS_ENCAP_NEXT_##s] = n,
	    foreach_iptfs_encap_next
#undef _
	},
};

VLIB_NODE_FN (iptfs_encap4_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iptfs_pkt_debug ("%s: Entering", __FUNCTION__);

  return iptfs_encap_enq_node_inline (vm, node, frame, 1,
				      IPTFS_ENABLE_ENCAP_MULTITHREAD);
}

VLIB_REGISTER_NODE (iptfs_encap4_tun_node) = {
    .name = "iptfs-encap4-tun",
    .flags = VLIB_NODE_FLAG_IS_OUTPUT | VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .vector_size = sizeof (u32),
    .format_trace = format_iptfs_encap_trace,

    .n_errors = ARRAY_LEN (iptfs_encap_error_strings),
    .error_strings = iptfs_encap_error_strings,

    .n_next_nodes = IPTFS_ENCAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
	{
#define _(s, n) [IPTFS_ENCAP_NEXT_##s] = n,
	    foreach_iptfs_encap_next
#undef _
	},
};

VLIB_NODE_FN (iptfs_encap6_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iptfs_pkt_debug ("%s: Entering", __FUNCTION__);

  return iptfs_encap_enq_node_inline (vm, node, frame, 1,
				      IPTFS_ENABLE_ENCAP_MULTITHREAD);
}

VLIB_REGISTER_NODE (iptfs_encap6_tun_node) = {
    .name = "iptfs-encap6-tun",
    .flags = VLIB_NODE_FLAG_IS_OUTPUT | VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .vector_size = sizeof (u32),
    .format_trace = format_iptfs_encap_trace,

    .n_errors = ARRAY_LEN (iptfs_encap_error_strings),
    .error_strings = iptfs_encap_error_strings,

    .n_next_nodes = IPTFS_ENCAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
	{
#define _(s, n) [IPTFS_ENCAP_NEXT_##s] = n,
	    foreach_iptfs_encap_next
#undef _
	},
};

VNET_FEATURE_INIT (iptfs_encap4_tun_feat_node, static) = {
    .arc_name = "ip4-output",
    .node_name = "iptfs-encap4-tun",
    .runs_before = VNET_FEATURES ("esp4-encrypt-tun", "dpdk-esp4-encrypt-tun"),
};

VNET_FEATURE_INIT (iptfs_encap6_tun_feat_node, static) = {
    .arc_name = "ip6-output",
    .node_name = "iptfs-encap6-tun",
    .runs_before = VNET_FEATURES ("esp6-encrypt-tun", "dpdk-esp6-encrypt-tun"),
};

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

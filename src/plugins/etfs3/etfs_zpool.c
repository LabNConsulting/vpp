/*
 * -*- coding: utf-8 -*-*
 * October 3 2019, Christian Hopps <chopps@labn.net>
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
#include <plugins/etfs3/etfs_zpool.h>
#include <plugins/etfs3/etfs_debug.h>

#if 0
char *etfs_event_type_strings[IPTFS_EVENT_N_TYPES] = {
#define _(sym, string) string,
    foreach_etfs_event_type
#undef _
};
#endif /* 0 */

#define foreach_etfs_zpool_error                                           \
  _ (ENTER_NOBUF, "ETFS-zpool-err zpool empty on refill")                  \
  _ (NOBUF, "ETFS-zpool-err can't allocate any buffers to fill zpool")     \
  _ (SHORTBUF, "ETFS-zpool-err can't allocate some buffers to fill zpool") \
  _ (UNKNOWN_EVENT, "ETFS unknown event to pad pool process")

typedef enum
{
#define _(sym, str) ETFS_ZPOOL_ERROR_##sym,
  foreach_etfs_zpool_error
#undef _
      ETFS_ZPOOL_N_ERROR,
} etfs_zpool_error_t;

static char *etfs_zpool_error_strings[] = {
#define _(sym, string) string,
    foreach_etfs_zpool_error
#undef _
};


/*
 * gets buffer pointers to newly allocated buffers
 */
static inline void
etfs_zpool_get_new_buffers(
    vlib_main_t		*vm,
    etfs_zpool_t	*zpool,
    vlib_buffer_t	**buffers,
    u32			n_alloc)
{
  const u32		ring_size = zpool->ring_size;
  u32			tail = zpool->tail;
  u32			new_tail = (tail + n_alloc) & (ring_size - 1);
  u32			n;

  if (tail > new_tail)
    {
      n = clib_min (ring_size - tail, n_alloc);
      vlib_get_buffers (vm, &zpool->buffers[tail], buffers, n);
      tail = 0;
      n_alloc -= n;
      buffers += n;
    }
  if (n_alloc)
    vlib_get_buffers (vm, &zpool->buffers[tail], buffers, n_alloc);
}

static inline u32
etfs_refill_zpool(
    vlib_main_t		*vm,
    etfs_zpool_t	*zpool,
    u32			req_payload_size,
    bool		put) /* set buf size to full (all-pad) */
{
  const u32 ring_size = zpool->ring_size;
  u32 nelm = etfs_zpool_get_avail (zpool);
  u32 tail = zpool->tail;
  u32 n, nreq;

  if (nelm > zpool->trigger)
    return 0;

  u32 payload_size = req_payload_size;

#if ETFS_PAD_SIZE_EXPERIMENT_1

  /* experiment for macsec on MB hw: pad to 4-byte multiple + 2 length */
  u16	off;
  if ((off = (payload_size & 0x3)) != 2) {
      payload_size += (6 - off) & 0x3;
  }
#endif

  ASSERT(payload_size <= vlib_buffer_get_default_data_size(vm));

  nreq = zpool->queue_size - nelm;
  n = vlib_buffer_alloc_to_ring (vm, zpool->buffers, tail, ring_size, nreq);
  if (n) {
      if (n < nreq) {
	  ETFS_DEBUG_F(ZPOOL, 3,
	      "%s: ZPOOL: less buffers allocated than requested %u<%u",
	      __func__, n, nreq);
      }

      vlib_buffer_t **b, **eb;
      vec_validate (zpool->tmp, n - 1);
      etfs_zpool_get_new_buffers (vm, zpool, zpool->tmp, n);

      u32	hdrlen = vec_len(zpool->header);

      for (b = zpool->tmp, eb = b + n; b < eb; b++) {
	  vlib_buffer_t *b0 = *b;

#if ETFS_ENABLE_BUFFER_NOTES
	  vlib_buffer_note_add(b0, "+%s", __func__);
#endif

	  u8	*payload;

	  if (hdrlen) {
	    /* assumes current_length is 0 */
	    payload = vlib_buffer_put_uninit(b0, hdrlen);
	    clib_memcpy_fast(payload, zpool->header, hdrlen);
	  }
	  /* danger: ensure payload_size doesn't exceed buffer space */
	  if (put)
		  payload = vlib_buffer_put_uninit(b0, payload_size);
	  else
		  payload = vlib_buffer_get_tail(b0);
	  clib_memset (payload, 0, payload_size);
	  vnet_buffer(b0)->sw_if_index[VLIB_TX] = zpool->if_index_tx;
	}
      _vec_len (zpool->tmp) = 0;
  } else {
      ETFS_DEBUG_F(ZPOOL, 3, "%s: got no buffers allocated to the ring",
	__func__);
  }

  CLIB_MEMORY_STORE_BARRIER ();
  zpool->tail = (tail + n) & (ring_size - 1);

#if ETFS_ENABLE_ELOG
  /* Log an event with our data for this run */
  ELOG_TYPE_DECLARE (e) = {
      .format = "etfs-refill-zpool sa_index %d before %d requested %d head "
		"%d tail %d",
      .format_args = "i4i4i4i4i4",
  };
  u32 *data = ETFS_ELOGP (&e, &zpool->track);
  *data++ = sa_index;
  *data++ = nelm;
  *data++ = nreq;
  *data++ = zpool->head;
  *data++ = zpool->tail;
#endif

  return n;
}

static inline u32
etfs_node_refill_zpool(
    vlib_main_t			*vm,
    u32				node_index,
    etfs_zpool_t		*zpool,
    u32				payload_size,
    bool			put)
{
    u32 avail = etfs_zpool_get_avail (zpool);

  if (PREDICT_FALSE (!avail))
    {
      vlib_node_increment_counter (vm, node_index,
				   ETFS_ZPOOL_ERROR_ENTER_NOBUF, 1);
#if ETFS_ENABLE_ELOG
      /* Log an event with our data for this run */
	u32 *data;
	ELOG_TYPE_DECLARE (e) = {
	  .format = "etfs-zpool-was-empty sa_index %d",
	  .format_args = "i4",
	};
	data = ETFS_ELOGP (&e, &zpool->error_track);
	*data++ = sa_index;
#endif
    }

  if (avail > zpool->trigger)
    return 0;

  u32 needed = zpool->queue_size - avail;
  u32 n = etfs_refill_zpool (vm, zpool, payload_size, put);
  if (PREDICT_FALSE (n < needed))
    {
      u32 error = !n ? ETFS_ZPOOL_ERROR_NOBUF : ETFS_ZPOOL_ERROR_SHORTBUF;
      vlib_node_increment_counter (vm, node_index, error, 1);

#if ETFS_ENABLE_ELOG
    /* Log an event with our data for this run */
    u32 *data;
    ELOG_TYPE_DECLARE (e) = {
      .format = "etfs-zpool-short-alloc sa_index %d asked %d got %d",
      .format_args = "i4i4i4",
    };
    data = ETFS_ELOGP (&e, &zpool->error_track);
    *data++ = sa_index;
    *data++ = needed;
    *data++ = n;
#endif
    }

  ETFS_DEBUG_F(ZPOOL, 3, "%s: refilled: before %u after %u",
		   __FUNCTION__, avail, avail + n);

  return n;
}

static u32
etfs_refill_zbuffers(
    vlib_main_t			*vm,
    u32				node_index,
    state_encap_flow_v2_t	*ef)
{
  u32 npkts = 0;

  npkts += etfs_node_refill_zpool (vm, node_index,
	ef->output.zpool, ef->config.framesize, true);
  npkts += etfs_node_refill_zpool (vm, node_index,
	ef->encap.zpool, ef->config.framesize, false);
  return npkts;
}

/*
 * Allocate a zpool to maintain queue_size zero'd buffers.
 */
etfs_zpool_t *
etfs_zpool_alloc(
    vlib_main_t		*vm,
    u32			queue_size,
    u32			payload_size,
    u8			*pPktHdr,	/* or NULL */
    u32			PktHdrLen,
    u32			if_index_tx,
    bool		put,
    elog_track_t	*track,
    elog_track_t	*error_track
    )
{
  etfs_zpool_t template = {
      .queue_size = queue_size,
      /* Ring size must always be power of 2 */
      .ring_size = max_pow2 (queue_size + 1),
      /* .trigger =
	  queue_size - ((queue_size <= VLIB_FRAME_SIZE * 2) ? queue_size / 8
							    : VLIB_FRAME_SIZE),
      */
      .trigger = queue_size - clib_min (VLIB_FRAME_SIZE, queue_size / 8),
      .if_index_tx = if_index_tx,
      .track = track,
      .error_track = error_track,
  };
  etfs_zpool_t *zpool =
      clib_mem_alloc_aligned (sizeof (*zpool), CLIB_CACHE_LINE_BYTES);
  clib_memcpy (zpool, &template, sizeof (*zpool));
  if (pPktHdr) {
      while (PktHdrLen--)
	vec_add1(zpool->header, *pPktHdr++);
  }

  vec_validate (zpool->buffers, zpool->ring_size - 1);
  if (queue_size != etfs_refill_zpool (vm, zpool, payload_size, put)) {
      etfs_zpool_free (vm, zpool);
      zpool = NULL;
  }
  return zpool;
}

void
etfs_zpool_free (vlib_main_t *vm, etfs_zpool_t *zpool)
{
  if (!zpool)
    return;

  /* free buffers in ring */
  u32 head = zpool->head;
  u32 tail = zpool->tail;

  if (zpool->header)
    vec_free(zpool->header);

  if (head > tail)
    {
      b_free_bi_chain (vm, &zpool->buffers[head], zpool->ring_size - head, "zf1");
      head = 0;
    }
  if (head != tail)
    b_free_bi_chain (vm, &zpool->buffers[head], tail - head, "zf2");
  vec_free (zpool->buffers);
  clib_mem_free (zpool);
}

/* ------------------ */
/* ZPOOL Polling Node */
/* ------------------ */

#if 0
static inline void
check_sa_pool_not_free_debug (u32 sa_index)
{
  pool_header_t *p = pool_header (ipsec_main.sad);
  int vl = vec_len (ipsec_main.sad);
  ASSERT (sa_index < vl);

  uword i0 = sa_index / BITS (p->free_bitmap[0]);
  uword i1 = sa_index % BITS (p->free_bitmap[0]);
  if (i0 < vec_len (p->free_bitmap))
    ASSERT (!((p->free_bitmap[i0] >> i1) & 1));

  ASSERT (!clib_bitmap_get (p->free_bitmap, sa_index));
}
#endif


/* *INDENT-OFF* */
VLIB_NODE_FN (etfs_zpool_poll_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    etfs_thread_main_t		*tm;
    state_encap_flow_v2_t	**ppEf;

    u32 npkts = 0;
    tm = vec_elt_at_index(etfs3_main.workers_main, vlib_get_thread_index());

    vec_foreach(ppEf, tm->flows[ETFS_ENCAP_POLLER_ZPOOL]) {
	npkts += etfs_refill_zbuffers(vm, node->node_index, *ppEf);
    }

    return npkts;
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (etfs_zpool_poll_node) = {
    .name = "etfs-zpool-poller",
    .vector_size = sizeof (u32),
#if 0 /* TBD */
    .format_trace = format_etfs_header_trace,
#endif
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_DISABLED,
    // XXX we don't actually support tracing here, the user will.
    // .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

    .n_errors = ETFS_ZPOOL_N_ERROR,
    .error_strings = etfs_zpool_error_strings,
};

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

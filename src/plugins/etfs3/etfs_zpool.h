/*
 * April 5 2020, Christian E. Hopps <chopps@labn.net>
 *
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
#ifndef __included_etfs_zpool_h__
#define __included_etfs_zpool_h__

#include <vlib/vlib.h>

/* TBD fixme */
#if 0
extern vlib_node_registration_t iptfs_zpool_poll_node;
extern vlib_node_registration_t iptfs_zpool_process_node;
#endif

/*
 * The ring is always power of 2, and can hold ringsize - 1 elements.
 *
 * So best to ask for 2^N - 1 qsize to be efficient.
 *
 * The code assumes only 1 writer and only 1 reader thread for efficient
 * lock-less operation.
 */
typedef struct etfs_zpool_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  const u32 queue_size; /* number of zeroed buffers to maintain */
  const u32 ring_size;	/* power of 2 ring size */
  const u32 trigger;	/* reload when queue_size is at or below trigger */
  volatile u32 tail;	/* read by one thread, written by zpool */
  volatile u32 head;	/* read by zpool written by one thread */
  u8 *header;		/* vector of bytes to put at start of buffers */
  u32 if_index_tx;	/* TX interface to init buffers, or ~0 means don't */
  u32 *buffers;		/* read by one thread, written by zpool */
  vlib_buffer_t **tmp;	/* internally used when refilling */
  elog_track_t *track;
  elog_track_t *error_track;
} etfs_zpool_t;

always_inline u32
etfs_zpool_get_avail (etfs_zpool_t *zpool)
{
  u32 head = zpool->head;
  u32 tail = zpool->tail;

  if (head > tail)
    return zpool->ring_size - (head - tail);
  else
    return tail - head;
}

#if 0
/*
 * Ping the zpool process, should only be done when running with no workers.
 */
always_inline void
iptfs_zpool_ping_nobuf (vlib_main_t *vm, u32 sa_index, iptfs_sa_data_t *satd)
{
  ASSERT (vlib_num_workers () == 0);
  if (PREDICT_TRUE (satd->tfs_pad_req_pending))
    return;
  satd->tfs_pad_req_pending = true;
  vlib_process_signal_event_mt (vm, iptfs_zpool_process_node.index,
				IPTFS_EVENT_TYPE_MORE_BUFFERS, sa_index);
}
#endif

always_inline u32
etfs_zpool_get_buffer (etfs_zpool_t *zpool)
{
  u32 bi0 = ~0u;
  u32 head;

  if ((head = zpool->head) != zpool->tail)
    {
      bi0 = zpool->buffers[head++];
      head = head & (zpool->ring_size - 1);

      /* I think we need to do a store barrier prior to updating the head */
      /* XXX although we aren't changing anything else. */
      CLIB_MEMORY_STORE_BARRIER ();
      zpool->head = head;
    }

  return bi0;
}

always_inline u32
etfs_zpool_get_buffers (etfs_zpool_t *zpool, u32 *buffers, u32 n_alloc,
			 bool partial_ok, elog_track_t *zpool_track)
{
  const u32 ring_size = zpool->ring_size;
  u32 head = zpool->head;
  u32 tail = zpool->tail;
  u32 n;

  u32 n_avail = etfs_zpool_get_avail (zpool);
  if (n_avail < n_alloc)
    {
#if ETFS_ENABLE_ELOG
      /* Log an event with our data for this run */
      ELOG_TYPE_DECLARE (event_err_zbuf) = {
	  .format = "low/no zbuf req %d avail %d head %d tail %d ringsize %d",
	  .format_args = "i4i4i4i4i4",
      };
      u32 *esd = IPTFS_ELOGP (&event_err_zbuf, zpool_track);
      *esd++ = n_alloc;
      *esd++ = n_avail;
      *esd++ = zpool->head;
      *esd++ = zpool->tail;
      *esd++ = zpool->ring_size;
#endif

      if (!n_avail)
	return 0;
      if (!partial_ok)
	return 0;
      n_alloc = n_avail;
    }

  u32 n_need = n_alloc;
  if (head > tail)
    {
      n = clib_min (ring_size - head, n_need);
      clib_memcpy_fast (buffers, &zpool->buffers[head], n * sizeof (u32));
      head = (head + n) & (ring_size - 1);
      n_need -= n;
      buffers += n;
    }
  if (n_need)
    {
      clib_memcpy_fast (buffers, &zpool->buffers[head], n_need * sizeof (u32));
      head = (head + n_need) & (ring_size - 1);
    }

  /* Do we need a store ordering fence here? */
  CLIB_MEMORY_STORE_BARRIER ();
  zpool->head = head;

#if ETFS_ENABLE_ELOG
  /* Log an event with our data for this run */
  ELOG_TYPE_DECLARE (event_get_zbuf) = {
      .format = "get zbuf req %d avail %d head %d tail %d ringsize %d",
      .format_args = "i4i4i4i4i4",
  };
  u32 *esd = IPTFS_ELOGP (&event_get_zbuf, zpool_track);
  *esd++ = n_alloc;
  *esd++ = n_avail;
  *esd++ = zpool->head;
  *esd++ = zpool->tail;
  *esd++ = zpool->ring_size;
#endif

  return n_alloc;
}


extern etfs_zpool_t *
etfs_zpool_alloc(
    vlib_main_t	*vm,
    u32		queue_size,
    u32		payload_size,
    u8		*pPktHdr,	/* or NULL */
    u32		PktHdrLen,
    u32		if_index_tx,
    bool	put,
    elog_track_t *track,
    elog_track_t *error_track);

extern void
etfs_zpool_free(vlib_main_t *vm, etfs_zpool_t *zpool);

#endif /* __included_iptfs_zpool_h__ */

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

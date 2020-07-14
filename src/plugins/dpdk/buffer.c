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

#include <unistd.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_vfio.h>
#include <rte_version.h>
#include <rte_malloc.h>

#include <vlib/vlib.h>
#include <dpdk/buffer.h>

#if DEBUG_BUFFER_NOTES
static void
dpdk_buffer_note_clear_mb (struct rte_mbuf *mb)
{
  BVT (clib_bihash_kv) kv;
  u8 *s;

  kv.key = (uintptr_t) mb;
  if (BV (clib_bihash_search) (&bdm.note_table, &kv, &kv))
    {
      printf ("warning: dpdk_buffer_note_clear_mb: search failed, mb %p\n",
	      mb);
      ASSERT (0);
      return;
    }
  s = (u8 *) (kv.value);
  if (s)
    {
      vec_free (s);
      kv.value = 0;

      /* should replace prior value */
      if (BV (clib_bihash_add_del) (&bdm.note_table, &kv, 1 /* add */ ))
	{
	  printf ("warning: dpdk_buffer_note_clear_mb: add failed, mb %p\n",
		  mb);
	}
    }
}

static void
addnote_one_inner (struct rte_mbuf *mb, struct rte_mbuf *mb_referencing,	/* parent, if
										   any */
		   const char *fmt, va_list * args)
{
  u8 *s;
  BVT (clib_bihash_kv) kv;
  uint16_t refcnt = rte_mbuf_refcnt_read (mb);
  int show_refcnt;

  show_refcnt = (refcnt != 1) || mb_referencing;

  kv.key = (uintptr_t) mb;
  kv.value = ~0;

  ASSERT (!BV (clib_bihash_search) (&bdm.note_table, &kv, &kv));

  s = (u8 *) (kv.value);
  if (show_refcnt)
    {
      if (mb_referencing)
	s = format (s, "%p->(%u) ", mb_referencing, refcnt);
      else
	s = format (s, "-?(%u) ", refcnt);
    }
  s = va_format (s, fmt, args);
  s = format (s, "%s", "\n");
  kv.value = (uintptr_t) s;

  /* should replace prior value */
  ASSERT (!BV (clib_bihash_add_del) (&bdm.note_table, &kv, 1 /* add */ ));
}

static void
dpdk_buffer_note_add_mb_v (struct rte_mbuf *mb, int follow_next,
			   const char *fmt, va_list * va)
{
  while (mb)
    {
      va_list cva;

      va_copy (cva, *va);
      addnote_one_inner (mb, 0, fmt, &cva);
      va_end (cva);
      if (RTE_MBUF_CLONED (mb))
	{
	  struct rte_mbuf *m_referenced;

	  m_referenced = rte_mbuf_from_indirect (mb);
	  va_copy (cva, *va);
	  addnote_one_inner (m_referenced, mb, fmt, &cva);
	  va_end (cva);
	}
      if (!follow_next)
	return;
      mb = mb->next;
    }
}

static void
dpdk_buffer_note_add_mb (struct rte_mbuf *mb, int follow_next,
			 char *format, ...)
{
  va_list va;

  va_start (va, format);
  dpdk_buffer_note_add_mb_v (mb, follow_next, format, &va);
  va_end (va);
}

#endif /* DEBUG_BUFFER_NOTES */

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

extern struct rte_mbuf *dpdk_mbuf_template_by_pool_index;
#ifndef CLIB_MARCH_VARIANT
struct rte_mempool **dpdk_mempool_by_buffer_pool_index = 0;
struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index = 0;
struct rte_mbuf *dpdk_mbuf_template_by_pool_index = 0;

clib_error_t *
dpdk_buffer_pool_init (vlib_main_t * vm, vlib_buffer_pool_t * bp)
{
  uword buffer_mem_start = vm->buffer_main->buffer_mem_start;
  struct rte_mempool *mp, *nmp;
  struct rte_pktmbuf_pool_private priv;
  enum rte_iova_mode iova_mode;
  u32 i;
  u8 *name = 0;

  u32 elt_size =
    sizeof (struct rte_mbuf) + sizeof (vlib_buffer_t) + bp->data_size;

  /* create empty mempools */
  vec_validate_aligned (dpdk_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (dpdk_no_cache_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);

  /* normal mempool */
  name = format (name, "vpp pool %u%c", bp->index, 0);
  mp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				 elt_size, 512, sizeof (priv),
				 bp->numa_node, 0);
  if (!mp)
    {
      vec_free (name);
      return clib_error_return (0,
				"failed to create normal mempool for numa node %u",
				bp->index);
    }
  vec_reset_length (name);

  /* non-cached mempool */
  name = format (name, "vpp pool %u (no cache)%c", bp->index, 0);
  nmp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				  elt_size, 0, sizeof (priv),
				  bp->numa_node, 0);
  if (!nmp)
    {
      rte_mempool_free (mp);
      vec_free (name);
      return clib_error_return (0,
				"failed to create non-cache mempool for numa nude %u",
				bp->index);
    }
  vec_free (name);

  dpdk_mempool_by_buffer_pool_index[bp->index] = mp;
  dpdk_no_cache_mempool_by_buffer_pool_index[bp->index] = nmp;

  mp->pool_id = nmp->pool_id = bp->index;

  rte_mempool_set_ops_byname (mp, "vpp", NULL);
  rte_mempool_set_ops_byname (nmp, "vpp-no-cache", NULL);

  /* Call the mempool priv initializer */
  memset (&priv, 0, sizeof (priv));
  priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    vlib_buffer_get_default_data_size (vm);
  priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);
  rte_pktmbuf_pool_init (nmp, &priv);

  iova_mode = rte_eal_iova_mode ();

  /* populate mempool object buffer header */
  for (i = 0; i < bp->n_buffers; i++)
    {
      struct rte_mempool_objhdr *hdr;
      vlib_buffer_t *b = vlib_get_buffer (vm, bp->buffers[i]);
      struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);
      hdr = (struct rte_mempool_objhdr *) RTE_PTR_SUB (mb, sizeof (*hdr));
      hdr->mp = mp;
      hdr->iova = (iova_mode == RTE_IOVA_VA) ?
	pointer_to_uword (mb) : vlib_physmem_get_pa (vm, mb);
      STAILQ_INSERT_TAIL (&mp->elt_list, hdr, next);
      /*
       * XXX: This almost seems too clever for it's own good, it works even
       * though it is using the same next field b/c the values assigned are the
       * same and the code never manipulates the list after initialization
       */
      STAILQ_INSERT_TAIL (&nmp->elt_list, hdr, next);
      mp->populated_size++;
      nmp->populated_size++;
#if DEBUG_BUFFER_NOTES
      BVT (clib_bihash_kv) note_search;
      note_search.key = (uintptr_t) mb;
      note_search.value = 0;
      BV (clib_bihash_add_del) (&bdm.note_table, &note_search, 1 /*add */ );
#endif
    }

  /* call the object initializers */
  rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);

  /* create mbuf header tempate from the first buffer in the pool */
  vec_validate_aligned (dpdk_mbuf_template_by_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  clib_memcpy (vec_elt_at_index (dpdk_mbuf_template_by_pool_index, bp->index),
	       rte_mbuf_from_vlib_buffer (vlib_buffer_ptr_from_index
					  (buffer_mem_start, *bp->buffers,
					   0)), sizeof (struct rte_mbuf));

  for (i = 0; i < bp->n_buffers; i++)
    {
      vlib_buffer_t *b;
      b = vlib_buffer_ptr_from_index (buffer_mem_start, bp->buffers[i], 0);
      vlib_buffer_copy_template (b, &bp->buffer_template);

      rte_pktmbuf_reset (rte_mbuf_from_vlib_buffer (b));
      b->flags |= VLIB_BUFFER_EXT_HDR_VALID;
    }

  /* map DMA pages if at least one physical device exists */
  if (rte_eth_dev_count_avail ())
    {
      uword i;
      size_t page_sz;
      vlib_physmem_map_t *pm;
      int do_vfio_map = 1;

      pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
      page_sz = 1ULL << pm->log2_page_size;

      for (i = 0; i < pm->n_pages; i++)
	{
	  char *va = ((char *) pm->base) + i * page_sz;
	  uword pa = (iova_mode == RTE_IOVA_VA) ?
	    pointer_to_uword (va) : pm->page_table[i];

	  if (do_vfio_map &&
#if RTE_VERSION < RTE_VERSION_NUM(19, 11, 0, 0)
	      rte_vfio_dma_map (pointer_to_uword (va), pa, page_sz))
#else
	      rte_vfio_container_dma_map (RTE_VFIO_DEFAULT_CONTAINER_FD,
					  pointer_to_uword (va), pa, page_sz))
#endif
	    do_vfio_map = 0;

	  struct rte_mempool_memhdr *memhdr;
	  memhdr = clib_mem_alloc (sizeof (*memhdr));
	  memhdr->mp = mp;
	  memhdr->addr = va;
	  memhdr->iova = pa;
	  memhdr->len = page_sz;
	  memhdr->free_cb = 0;
	  memhdr->opaque = 0;

	  STAILQ_INSERT_TAIL (&mp->mem_list, memhdr, next);
	  mp->nb_mem_chunks++;
	}
    }

  return 0;
}

static int
dpdk_ops_vpp_alloc (struct rte_mempool *mp)
{
  clib_warning ("");
  return 0;
}

static void
dpdk_ops_vpp_free (struct rte_mempool *mp)
{
  clib_warning ("");
}

#endif

static_always_inline void
dpdk_ops_vpp_enqueue_one (vlib_buffer_t * bt, void *obj)
{
  /* Only non-replicated packets (b->ref_count == 1) expected */

  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  ASSERT (b->ref_count == 1);
  ASSERT (b->buffer_pool_index == bt->buffer_pool_index);
  vlib_buffer_copy_template (b, bt);
#if DEBUG_BUFFER_NOTES
  dpdk_buffer_note_add_mb (mb, 0, "dpdk_ops_vpp_enqueue_one");
#endif
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue) (struct rte_mempool * mp,
					  void *const *obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t bt;
  u8 buffer_pool_index = mp->pool_id;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  u32 bufs[batch_size];
  u32 n_left = n;
  void *const *obj = obj_table;

  vlib_buffer_copy_template (&bt, &bp->buffer_template);

  while (n_left >= 4)
    {
      dpdk_ops_vpp_enqueue_one (&bt, obj[0]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[1]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[2]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[3]);
      obj += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      dpdk_ops_vpp_enqueue_one (&bt, obj[0]);
      obj += 1;
      n_left -= 1;
    }

  while (n >= batch_size)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   batch_size,
					   sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, batch_size);
      n -= batch_size;
      obj_table += batch_size;
    }

  if (n)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   n, sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, n);
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_enqueue);

static_always_inline void
dpdk_ops_vpp_enqueue_no_cache_one (vlib_main_t * vm, struct rte_mempool *old,
				   struct rte_mempool *new, void *obj,
				   vlib_buffer_t * bt)
{
  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);

  if (clib_atomic_sub_fetch (&b->ref_count, 1) == 0)
    {
#if DEBUG_BUFFER_NOTES
      dpdk_buffer_note_add_mb (mb, 0, "dpdk_ops_vpp_enqueue_no_cache_one r0");
#endif
      u32 bi = vlib_get_buffer_index (vm, b);
      vlib_buffer_copy_template (b, bt);
      vlib_buffer_pool_put (vm, bt->buffer_pool_index, &bi, 1);
      return;
    }
#if DEBUG_BUFFER_NOTES
  else
    {
      dpdk_buffer_note_add_mb (mb, 0, "dpdk_ops_vpp_enqueue_no_cache_one r!");
    }
#endif
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue_no_cache) (struct rte_mempool * cmp,
						   void *const *obj_table,
						   unsigned n)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t bt;
  struct rte_mempool *mp;
  mp = dpdk_mempool_by_buffer_pool_index[cmp->pool_id];
  u8 buffer_pool_index = cmp->pool_id;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  vlib_buffer_copy_template (&bt, &bp->buffer_template);

  while (n >= 4)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[0], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[1], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[2], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[3], &bt);
      obj_table += 4;
      n -= 4;
    }

  while (n)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[0], &bt);
      obj_table += 1;
      n -= 1;
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_enqueue_no_cache);

static_always_inline void
dpdk_mbuf_init_from_template (struct rte_mbuf **mba, struct rte_mbuf *mt,
			      int count)
{
  /* Assumptions about rte_mbuf layout */
  STATIC_ASSERT_OFFSET_OF (struct rte_mbuf, buf_addr, 0);
  STATIC_ASSERT_OFFSET_OF (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF_ELT (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF_ELT (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF (struct rte_mbuf, 128);

  while (count--)
    {
      struct rte_mbuf *mb = mba[0];
      int i;
      /* bytes 0 .. 15 hold buf_addr and buf_iova which we need to preserve */
      /* copy bytes 16 .. 31 */
      *((u8x16 *) mb + 1) = *((u8x16 *) mt + 1);

      /* copy bytes 32 .. 127 */
#ifdef CLIB_HAVE_VEC256
      for (i = 1; i < 4; i++)
	*((u8x32 *) mb + i) = *((u8x32 *) mt + i);
#else
      for (i = 2; i < 8; i++)
	*((u8x16 *) mb + i) = *((u8x16 *) mt + i);
#endif
      mba++;
    }
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_dequeue) (struct rte_mempool * mp,
					  void **obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  u32 bufs[batch_size], total = 0, n_alloc = 0;
  u8 buffer_pool_index = mp->pool_id;
  void **obj = obj_table;
  struct rte_mbuf t = dpdk_mbuf_template_by_pool_index[buffer_pool_index];

  while (n >= batch_size)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, batch_size,
					     buffer_pool_index);
      if (n_alloc != batch_size)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj, batch_size,
				    -(i32) sizeof (struct rte_mbuf));
      dpdk_mbuf_init_from_template ((struct rte_mbuf **) obj, &t, batch_size);
      total += batch_size;
      obj += batch_size;
      n -= batch_size;
    }

  if (n)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, n, buffer_pool_index);

      if (n_alloc != n)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj, n,
				    -(i32) sizeof (struct rte_mbuf));
      dpdk_mbuf_init_from_template ((struct rte_mbuf **) obj, &t, n);
    }
#if DEBUG_BUFFER_NOTES
  else
    {
      n_alloc = 0;
    }
  for (obj = obj_table, n = total + n_alloc; n; --n, ++obj)
    {
      struct rte_mbuf *mb;

      mb = (struct rte_mbuf *) *obj;
      dpdk_buffer_note_clear_mb (mb);
      dpdk_buffer_note_add_mb (mb, 0, "dpdk_ops_vpp_dequeue (refcnt %u)",
			       rte_mbuf_refcnt_read (mb));
    }
#endif

  return 0;

alloc_fail:
  /* dpdk doesn't support partial alloc, so we need to return what we
     already got */
  if (n_alloc)
    vlib_buffer_pool_put (vm, buffer_pool_index, bufs, n_alloc);
  obj = obj_table;
  while (total)
    {
      vlib_get_buffer_indices_with_offset (vm, obj, bufs, batch_size,
					   sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, batch_size);

      obj += batch_size;
      total -= batch_size;
    }
  return -ENOENT;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_dequeue);

#ifndef CLIB_MARCH_VARIANT

static int
dpdk_ops_vpp_dequeue_no_cache (struct rte_mempool *mp, void **obj_table,
			       unsigned n)
{
  clib_error ("bug");
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count (const struct rte_mempool *mp)
{
  clib_warning ("");
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count_no_cache (const struct rte_mempool *mp)
{
  struct rte_mempool *cmp;
  cmp = dpdk_no_cache_mempool_by_buffer_pool_index[mp->pool_id];
  return dpdk_ops_vpp_get_count (cmp);
}

/*
 * Note! This function does not manage offsets/lengths of the data area.
 * Caller must set as needed.
 */
static void
dpdk_buffer_attach (vlib_buffer_t * b_referencing,
		    vlib_buffer_t * b_referenced)
{
  struct rte_mbuf *mb_referencing;
  struct rte_mbuf *mb_referenced;

  mb_referencing = rte_mbuf_from_vlib_buffer (b_referencing);
  mb_referenced = rte_mbuf_from_vlib_buffer (b_referenced);

  /* we don't allow multiple indirections */
  ASSERT ((b_referenced->flags & VLIB_BUFFER_INDIRECT) == 0);

  /* referencing buffer must not already be indirect */
  ASSERT ((b_referencing->flags & VLIB_BUFFER_INDIRECT) == 0);

  // XXX chopps: this seems wrong to require this, the attach we
  // XXX chopps: are about to do will effectively reset the referencing
  // XXX chopps: mbuf so instead of require the flag we should set it.
  /* dpdk_validate_rte_mbuf() should not call rte_pktmbuf_reset() */
  // ASSERT (b_referencing->flags & VLIB_BUFFER_EXT_HDR_VALID);

  // XXX chopps: however, we *should* require that it be set on the
  // XXX chopps: referenced buffer.
  if ((b_referenced->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0)
    {
      /* We get here if the packet didn't come from DPDK, e.g., locall generated
         or testing pg). */
      /* If we've already attached to this buffer it needs to be valid */
      ASSERT ((b_referenced->flags & VLIB_BUFFER_ATTACHED) == 0);
      rte_pktmbuf_reset (mb_referenced);
      b_referenced->flags |= VLIB_BUFFER_EXT_HDR_VALID;
    }

  rte_pktmbuf_attach (mb_referencing, mb_referenced);
  b_referencing->flags |= VLIB_BUFFER_EXT_HDR_VALID | VLIB_BUFFER_INDIRECT;
  b_referenced->flags |= VLIB_BUFFER_ATTACHED;

  /*
   * The data area of the referencing buffer is now unused. As a
   * temporary hack while the ethernet driver(s) lack support for
   * multi-segment buffers, we will write the pointer to the referenced
   * vlib buffer at b->data[0] with guard data on either side equal
   * to the referencing buffer pointer.
   *
   * etfs3 uses this pointer to find the referenced buffer at the
   * last moment before transmitting.
   *
   */
  clib_memcpy (b_referencing->data, &b_referenced, sizeof (b_referenced));
  clib_memcpy (b_referencing->data + sizeof (b_referenced), &b_referencing,
	       sizeof (b_referencing));
  clib_memcpy (b_referencing->data - sizeof (b_referencing),
	       &b_referencing, sizeof (b_referencing));

#if DEBUG_BUFFER_NOTES
  dpdk_buffer_note_add_mb (mb_referencing, 0,
			   "post dpdk_buffer_attach %p->%p", mb_referencing,
			   mb_referenced);
#endif
}

static void
dpdk_buffer_detach (vlib_buffer_t * b_referencing)
{
  struct rte_mbuf *mb_referencing;

  mb_referencing = rte_mbuf_from_vlib_buffer (b_referencing);

  rte_pktmbuf_detach (mb_referencing);
  b_referencing->flags &= ~VLIB_BUFFER_INDIRECT;

}

static void
dpdk_buffer_free (vlib_buffer_t * b)
{
  struct rte_mbuf *mb;

  mb = rte_mbuf_from_vlib_buffer (b);

#if DEBUG_BUFFER_NOTES
  dpdk_buffer_note_add_mb (mb, 1, "dpdk_buffer_free pre");
#endif
  rte_pktmbuf_free (mb);
}

static void
dpdk_buffer_free_seg (vlib_buffer_t * b)
{
  struct rte_mbuf *mb;
  extern format_function_t format_chained_rte_mbuf;

  mb = rte_mbuf_from_vlib_buffer (b);
#if DEBUG_BUFFER_NOTES
  dpdk_buffer_note_add_mb (mb, 0, "dpdk_buffer_free_seg pre");
#endif
  rte_pktmbuf_free_seg (mb);
}

#if DEBUG_BUFFER_NOTES

static void
dpdk_buffer_note_add_b_v (vlib_buffer_t * b, char *format, va_list *va)
{
  struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);

  dpdk_buffer_note_add_mb_v (mb, 0, format, va);
}

static void
dpdk_buffer_note_clear_b (vlib_buffer_t * b)
{
  struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);

  dpdk_buffer_note_clear_mb (mb);
}

static void
dpdk_buffer_note_dump_b (vlib_buffer_t * b)
{
  struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);
  u8 *s;
  BVT (clib_bihash_kv) kv;

  kv.key = (uintptr_t) mb;
  if (BV (clib_bihash_search) (&bdm.note_table, &kv, &kv))
    {
      printf ("warning: dpdk_buffer_note_dump: search failed\n");
      return;
    }
  s = (u8 *) (kv.value);
  printf ("mb %p:\n%s%c", mb, s, 0);
  fflush(stdout);
}

static u8 *
dpdk_buffer_format_note (u8 * s, vlib_buffer_t * b)
{
  struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);
  BVT (clib_bihash_kv) kv;

  kv.key = (uintptr_t) mb;
  if (BV (clib_bihash_search) (&bdm.note_table, &kv, &kv))
    s = format (s, "mb %p: note: NONE", mb);
  else
    s = format (s, "MB %p note: %s", mb, (u8 *) (kv.value));
  return s;
}

static u32 buffer_note_dump_bulk_count = 0;

static int
buffer_note_dump_bulk_callback (BVT (clib_bihash_kv) * kv, void *arg)
{
  if (buffer_note_dump_bulk_count)
    {
      struct rte_mbuf *mb = (struct rte_mbuf *) kv->key;
      u8 *s = (u8 *) (kv->value);
      --buffer_note_dump_bulk_count;
      printf ("mb %p:\n%s%c", mb, (s ? (char *) s : ""), 0);
      fflush(stdout);
      return BIHASH_WALK_CONTINUE;
    }
  return BIHASH_WALK_STOP;
}

static void
dpdk_buffer_note_dump_bulk (u32 count)
{
  buffer_note_dump_bulk_count = count;

  BV (clib_bihash_foreach_key_value_pair) (&bdm.note_table,
					   buffer_note_dump_bulk_callback, 0);
}
#endif /* DEBUG_BUFFER_NOTES */

static i32
dpdk_buffer_get_mbuf_refcount (vlib_buffer_t * b)
{
  return rte_mbuf_refcnt_read (rte_mbuf_from_vlib_buffer (b));
}


typedef struct {
    const struct rte_memzone	*mz;
    void			*vaddr;
    rte_iova_t			iova;
    uint64_t			len;
} pad_buffer_info_t;

static void
dpdk_pad_buffer_free_cb(void *addr, void *opaque)
{
    pad_buffer_info_t	*pbi;

    pbi = (pad_buffer_info_t *)opaque;

    ASSERT(pbi->vaddr == addr);

    if (pbi->vaddr != (void *)pbi->iova) { /* See corresponding test in init code below */
	if (rte_vfio_is_enabled("vfio")) { /* magic str from linux/eal/eal.c */
#if RTE_VERSION < RTE_VERSION_NUM(19, 11, 0, 0)
	    rte_vfio_dma_unmap(pointer_to_uword(pbi->vaddr), pbi->iova, pbi->len);
#else
	    rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
	      pointer_to_uword(pbi->vaddr), pbi->iova, pbi->len);
#endif
	}
    }

    rte_memzone_free(pbi->mz);
}

/*
 * Allocate a new vlib buffer and attach the caller-supplied buffer
 * as an "extbuf". Use the tail of the caller-supplied buffer for
 * the struct rte_mbuf_ext_shared_info area (refcount, free callback).
 * Zeroes the buffer data area.
 */
static int
dpdk_pad_buffer_init (
    u16 request_bufsize,
    u32 * new_vlib_bi)
{
  vlib_main_t				*vm = vlib_get_main ();
  u32					bi;
  vlib_buffer_t				*b;
  struct rte_mbuf			*mb;
  struct rte_mbuf_ext_shared_info	*shinfo;
  u16					total_bufsize;
  u16					buf_len;
  rte_iova_t				pad_buffer_iova;
  void					*pad_buffer;
  const struct rte_memzone		*mz;
  pad_buffer_info_t			*pbi;
  int					rc;
  char					mz_name[sizeof(mz->name)];
  int					is_physical = 0;

  /*
   * Compute total memory needed, which comprises:
   * 1. our private header with memzone info + alignment overhead
   * 2. caller's requested size
   * 3. rte_mbuf struct rte_mbuf_ext_shared_info + alignment overhead
   *
   * Conservative estimate: head and tail structure each require
   * equivalent-sized alignment padding.
   */
  total_bufsize =
    (2 * sizeof(pad_buffer_info_t)) +
    request_bufsize +
    (2 * sizeof(struct rte_mbuf_ext_shared_info));

  /*
   * We are obligated to assign a unique name to each reserved memzone.
   * One approach would be to use something like etfs-pad-NNNN where NNNN
   * is the etfs flow number. However, that would require passing the
   * flow number from etfs into this init code. Not difficult, but requires
   * touching the dpdk_pad_buffer_init callback signature in several places.
   *
   * Instead, let's just use a running 64-bit unsigned counter to make a
   * unique name string every time. Resulting string must fit in the mz->name
   * field.
   */
  static u64 pad_serial;

  if (snprintf(mz_name, sizeof(mz_name), "etfs-pad-%lx", pad_serial) >=
    sizeof(mz_name)) {

     clib_error("%s: name of pad buffer memzone too long (limit %d)",
	__func__, sizeof(mz_name) - 1);
     return -1;
  }
  pad_serial += 1;

  mz = rte_memzone_reserve (mz_name, total_bufsize, SOCKET_ID_ANY,
			    RTE_MEMZONE_IOVA_CONTIG | RTE_MEMZONE_2MB |
			    RTE_MEMZONE_SIZE_HINT_ONLY);
  if (mz == NULL) {
    clib_error("%s: rte_memzone_reserve failed\n", __func__);
    return -1;
  }

  /*
   * detect if reserved memory addr is already physical address
   */
  is_physical = (mz->addr == (void *)mz->iova);

  /*
   * Store our meta-info at the start of the allocated buffer
   */
  pbi = (pad_buffer_info_t *)RTE_PTR_ALIGN_CEIL(mz->addr, sizeof(void *));
  clib_memset(pbi, 0, sizeof(*pbi));
  pbi->mz = mz;

  /*
   * user data area starts after our metadata area
   */
  pad_buffer = (void *)(pbi + 1);

  /* buf_len = total_bufsize - RTE_PTR_DIFF(pbi, mz->addr); wrong? */
  buf_len = total_bufsize - RTE_PTR_DIFF(pad_buffer, mz->addr);

  /*
   * shinfo is the mbuf extbuf metadata which is stored at the
   * end of the user data area.
   *
   * buf_len is modified to reflect size of caller-usable data area
   */
  shinfo = rte_pktmbuf_ext_shinfo_init_helper (pad_buffer, &buf_len,
    dpdk_pad_buffer_free_cb, pbi);

  if (!shinfo) {
    rte_memzone_free(mz);
    clib_error("%s: rte_pktmbuf_ext_shinfo_init_helper failed\n", __func__);
    return -1;
  }
  ASSERT(buf_len >= request_bufsize);

  u32 n = vlib_buffer_alloc (vm, &bi, 1);
  if (!n) {
    rte_memzone_free(mz);
    clib_error("%s: vlib_buffer_alloc failed\n", __func__);
    return -1;
  }

  b = vlib_get_buffer (vm, bi);
  mb = rte_mbuf_from_vlib_buffer (b);
  rte_pktmbuf_reset (mb);	/* port<-INVALID so drivers don't misbehave */
  b->flags |= VLIB_BUFFER_EXT_HDR_VALID;

  memset (pad_buffer, 0, buf_len);

  /*
   * Can't rte_malloc_virt2iova(arbitrary address) to get iov addr.
   * Fortunately, rte_memzone_reserve() already provides iova of its
   * allocation, so just calculate offset from that.
   */
  pad_buffer_iova = mz->iova + (RTE_PTR_DIFF(pad_buffer, mz->addr));

  /*
   * gpz 200724 speculative fix: I *think* vfio mapping should be done
   * only if pad_buffer is not a physical address.
   */
  if (!is_physical) {
      /*
       * gpz: I haven't tested rte_vfio_is_enabled() on x86 yet. The conditional
       * is correctly false on MB.
       */
      if (rte_vfio_is_enabled("vfio")) { /* magic str from linux/eal/eal.c */
#if RTE_VERSION < RTE_VERSION_NUM(19, 11, 0, 0)
	  rc = rte_vfio_dma_map(
	    pointer_to_uword(pad_buffer), pad_buffer_iova, buf_len);
#else
	  rc = rte_vfio_container_dma_map (RTE_VFIO_DEFAULT_CONTAINER_FD,
	    pointer_to_uword (pad_buffer), pad_buffer_iova, buf_len);
#endif
	  if (rc < 0) {
	    /* mapping failed, unwind everything */
	    vlib_buffer_free(vm, &bi, 1);
	    rte_memzone_free(mz);
	    clib_error("%s: rte_vfio_dma_map failed\n", __func__);
	    return -1;
	  }
      }
  }

  pbi->vaddr = pad_buffer;
  pbi->iova = pad_buffer_iova;
  pbi->len = buf_len;

#if DEBUG_BUFFER_NOTES
  dpdk_buffer_note_add_mb (mb, 0, "dma map %u bytes %p -> %p\n", buf_len,
			   (void *) pointer_to_uword (pad_buffer),
			   (void *) pad_buffer_iova);
#endif

  rte_pktmbuf_attach_extbuf (mb, pad_buffer, pad_buffer_iova, buf_len,
			     shinfo);

  *new_vlib_bi = bi;

  return 0;
}

clib_error_t *
dpdk_buffer_pools_create (vlib_main_t * vm)
{
  clib_error_t *err;
  vlib_buffer_pool_t *bp;

#if DEBUG_BUFFER_NOTES
  BV (clib_bihash_init)
    (&bdm.note_table, "buffer debug note table", 1024 * 1024 * 1024 / 10240,
     1024 * 1024 * 1024 / 10240 * 64 * 8);
#endif

  struct rte_mempool_ops ops = { };

  strncpy (ops.name, "vpp", 4);
  ops.alloc = dpdk_ops_vpp_alloc;
  ops.free = dpdk_ops_vpp_free;
  ops.get_count = dpdk_ops_vpp_get_count;
  ops.enqueue = CLIB_MARCH_FN_POINTER (dpdk_ops_vpp_enqueue);
  ops.dequeue = CLIB_MARCH_FN_POINTER (dpdk_ops_vpp_dequeue);
  rte_mempool_register_ops (&ops);

  strncpy (ops.name, "vpp-no-cache", 13);
  ops.get_count = dpdk_ops_vpp_get_count_no_cache;
  ops.enqueue = CLIB_MARCH_FN_POINTER (dpdk_ops_vpp_enqueue_no_cache);
  ops.dequeue = dpdk_ops_vpp_dequeue_no_cache;
  rte_mempool_register_ops (&ops);

  /* *INDENT-OFF* */
  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->start && (err = dpdk_buffer_pool_init (vm, bp)))
      return err;
  /* *INDENT-ON* */

  /* Indirect data support */
  vlib_dpdk_callbacks_t cb;
  clib_memset (&cb, 0, sizeof (cb));

  cb.buffer_attach = dpdk_buffer_attach;
  cb.buffer_detach = dpdk_buffer_detach;
  cb.buffer_free = dpdk_buffer_free;
  cb.buffer_free_seg = dpdk_buffer_free_seg;
#if DEBUG_BUFFER_NOTES
  cb.buffer_note_add_v = dpdk_buffer_note_add_b_v;
  cb.buffer_note_clear = dpdk_buffer_note_clear_b;
  cb.buffer_note_dump = dpdk_buffer_note_dump_b;
  cb.buffer_note_dump_bulk = dpdk_buffer_note_dump_bulk;
  cb.buffer_format_note = dpdk_buffer_format_note;
#endif
  cb.buffer_get_mbuf_refcount = dpdk_buffer_get_mbuf_refcount;
  cb.buffer_pad_buffer_init = dpdk_pad_buffer_init;

  vlib_buffer_register_dpdk_callbacks (vm, &cb);

  return 0;
}

VLIB_BUFFER_SET_EXT_HDR_SIZE (sizeof (struct rte_mempool_objhdr) +
			      sizeof (struct rte_mbuf));

#endif

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

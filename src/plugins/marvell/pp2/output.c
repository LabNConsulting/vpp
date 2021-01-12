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

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <marvell/pp2/pp2.h>


static_always_inline u32
mrvl_pp2_get_num_outq_done(mrvl_pp2_per_thread_data_t *ptd, mrvl_pp2_if_t *ppif, u8 qid)
{
  u16 num;
  int err = pp2_ppio_get_num_outq_done (ppif->ppio, ptd->hif, qid, &num);
  if (PREDICT_FALSE(err))
    abort();
  return num;
}

static_always_inline
u16 mrvl_pp2_send(struct pp2_ppio *ppio, struct pp2_hif *hif, u8 qid, struct pp2_ppio_desc *descs, u16 num)
{
  int err = pp2_ppio_send(ppio, hif, qid, descs, &num);
  if (PREDICT_FALSE(err))
    abort();
  return num;
}

VNET_DEVICE_CLASS_TX_FN(mrvl_pp2_device_class) (vlib_main_t * vm,
                                                vlib_node_runtime_t * node,
                                                vlib_frame_t * frame)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, rd->dev_instance);
  u32 thread_index = vm->thread_index;
  mrvl_pp2_per_thread_data_t *ptd =
    vec_elt_at_index (ppm->per_thread_data, thread_index);
  u8 qid = thread_index;
  mrvl_pp2_outq_t *outq = vec_elt_at_index (ppif->outqs, qid);
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_desc = frame->n_vectors, n_left = n_desc, n_sent = n_desc, n_done;
  struct pp2_ppio_desc *d;
  u16 qsize = _vec_len(outq->buffers);

  n_done = mrvl_pp2_get_num_outq_done (ptd, ppif, qid);
  if (n_done)
    {
      if (PREDICT_FALSE(n_done > outq->n_enq))
        {
          clib_warning("done %u > n_enq %u", n_done, outq->n_enq);
          abort();
        }
      vlib_buffer_free_from_ring (vm, outq->buffers, mrvl_pp2_outq_start(outq),
                                  qsize, n_done);
      outq->n_enq -= n_done;
    }

  u16 capacity = qsize - outq->n_enq;
  if (n_left > capacity)
      n_left = capacity;

  vec_validate_aligned (ptd->descs, n_left, CLIB_CACHE_LINE_BYTES);
  d = ptd->descs;
  while (n_left)
    {
      u32 bi0 = buffers[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      u64 paddr = vlib_buffer_get_pa (vm, b0);

      pp2_ppio_outq_desc_reset (d);
      pp2_ppio_outq_desc_set_phys_addr (d, paddr + b0->current_data);
      pp2_ppio_outq_desc_set_pkt_offset (d, 0);
      pp2_ppio_outq_desc_set_pkt_len (d, b0->current_length);
      d++;
      buffers++;
      n_left--;
    }

  n_sent = mrvl_pp2_send (ppif->ppio, ptd->hif, qid, ptd->descs, n_sent);

  /* free unsent buffers */
  if (PREDICT_FALSE (n_sent != n_desc))
    {
      mrvl_pp2_debug("Failed to send %u packets", n_desc - n_sent);
      vlib_buffer_free (vm, vlib_frame_vector_args (frame) + n_sent,
			n_desc - n_sent);
      vlib_error_count (vm, node->node_index, MRVL_PP2_TX_ERROR_NO_FREE_SLOTS,
			n_desc - n_sent);
    }

  /* store buffer index for each enqueued packet into the ring
     so we can know what to free after packet is sent */
  if (n_sent)
    {
      buffers = vlib_frame_vector_args (frame);
      if (PREDICT_TRUE(outq->next + n_sent <= qsize))
        {
          vlib_buffer_copy_indices (outq->buffers + outq->next, buffers, n_sent);
          outq->next += n_sent;
          if (outq->next == qsize)
            outq->next = 0;
        }
      else
        {
          u16 n_copy = qsize - outq->next;
          vlib_buffer_copy_indices (outq->buffers + outq->next, buffers, n_copy);
          vlib_buffer_copy_indices (outq->buffers, buffers + n_copy,
                                    n_sent - n_copy);
          outq->next = n_sent - n_copy;
          if (PREDICT_FALSE(outq->next >= qsize))
            abort();
        }
      outq->n_enq += n_sent;
    }

  return n_desc;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

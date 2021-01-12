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

#define MVCONF_DBG_LEVEL 0
#define MVCONF_PP2_BPOOL_COOKIE_SIZE 32
#define MVCONF_PP2_BPOOL_DMA_ADDR_SIZE 64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE 64
#define MVCONF_SYS_DMA_UIO
#define MVCONF_TYPES_PUBLIC
#define MVCONF_DMA_PHYS_ADDR_T_PUBLIC

#include <vlib/vlib.h>

#include "mv_std.h"
#include "env/mv_sys_dma.h"
#include "drivers/mv_pp2.h"
#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_ppio.h>

#define MRVL_PP2_DEBUG
//#define MRVL_PP2_PKT_DEBUG

#define mrvl_pp2_log(...) clib_warning (__VA_ARGS__)
#ifdef MRVL_PP2_DEBUG
#define mrvl_pp2_debug(...) clib_warning (__VA_ARGS__)
#ifdef MRVL_PP2_PKT_DEBUG
#define mrvl_pp2_pkt_debug(...) clib_warning (__VA_ARGS__)
#else /* MRVL_PP2_PKT_DEBUG */
#define mrvl_pp2_pkt_debug(...)
#endif /* MRVL_PP2_PKT_DEBUG */
#else /* MRVL_PP2_DEBUG */
#define mrvl_pp2_debug(...)
#define mrvl_pp2_pkt_debug(...)
#endif /* MRVL_PP2_DEBUG */

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  u8 buffer_pool_index;
  struct pp2_bpool *bpool;
} mrvl_pp2_inq_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 next;
  u16 n_enq;
  u32 *buffers;
} mrvl_pp2_outq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
#define MRVL_PP2_IF_F_ADMIN_UP (1 << 0)
  struct pp2_ppio *ppio;
  u32 per_interface_next_index;

  mrvl_pp2_inq_t *inqs;
  mrvl_pp2_outq_t *outqs;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
} mrvl_pp2_if_t;

static inline u32
mrvl_pp2_outq_start(mrvl_pp2_outq_t *q)
{
  if (q->n_enq == 0)
    return 0;
  else if (q->n_enq > q->next)
    return _vec_len (q->buffers) + q->next - q->n_enq;
  else
    return q->next - q->n_enq;
}

static inline void
mrvl_pp2_outq_ndeq(mrvl_pp2_outq_t *q, u32 count)
{
  ASSERT(count < q->n_enq);
  q->n_enq -= count;
}

#define mrv_pp2_outq_size(q) _vec_len((q)->buffers)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct pp2_hif *hif;
  struct pp2_ppio_desc *descs;
  struct buff_release_entry bre[VLIB_FRAME_SIZE];
  u32 bi[VLIB_FRAME_SIZE];
  int last_bppe;
  vlib_buffer_t buffer_template;
  vlib_buffer_t *bp[VLIB_FRAME_SIZE];
} mrvl_pp2_per_thread_data_t;

typedef struct
{
  mrvl_pp2_if_t *interfaces;
  mrvl_pp2_per_thread_data_t *per_thread_data;

  /* API message ID base */
  u16 msg_id_base;
} mrvl_pp2_main_t;

extern vnet_device_class_t mrvl_pp2_device_class;
extern mrvl_pp2_main_t mrvl_pp2_main;

typedef struct
{
  u8 *name;
  u16 rx_q_sz;
  u16 tx_q_sz;

  /* return */
  i32 rv;
  u32 sw_if_index;
  clib_error_t *error;
} mrvl_pp2_create_if_args_t;

void mrvl_pp2_create_if (mrvl_pp2_create_if_args_t * args);
void mrvl_pp2_delete_if (mrvl_pp2_if_t * dfif);
clib_error_t *mrvl_pp2_plugin_api_hookup (vlib_main_t * vm);

/* output.c */

#define foreach_mrvl_pp2_tx_func_error \
  _(NO_FREE_SLOTS, "no free tx slots")			\
  _(PPIO_SEND, "pp2_ppio_send errors")			\
  _(PPIO_GET_NUM_OUTQ_DONE, "pp2_ppio_get_num_outq_done errors")

typedef enum
{
#define _(f,s) MRVL_PP2_TX_ERROR_##f,
  foreach_mrvl_pp2_tx_func_error
#undef _
    MRVL_PP2_TX_N_ERROR,
} mrvl_pp2_tx_func_error_t;

uword mrvl_pp2_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame);

/* input.c */

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  struct pp2_ppio_desc desc;
} mrvl_pp2_input_trace_t;

#define vlib_put_next_frame(vm, node, ni, to, eto)                      \
  do                                                                    \
    {                                                                   \
      if ((to))                                                         \
        vlib_put_next_frame ((vm), (node), (ni), (eto) - (to));         \
    }                                                                   \
  while (0)

#define vlib_put_get_next_frame(vm, node, ni, to, eto)               \
  do                                                                 \
    {                                                                \
      /* Put the frame if it is full */                              \
      if ((to) && (eto) != (to))                                     \
	;                                                            \
      else                                                           \
	{                                                            \
	  vlib_put_next_frame (vm, node, ni, to, eto);               \
	  vlib_get_next_frame_p ((vm), (node), (ni), (to), (eto));   \
	}                                                            \
    }                                                                \
  while (0)

#define vlib_put_get_next_frame_a(vm, node, ni, toa, etoa)           \
  vlib_put_get_next_frame (vm, node, ni, (toa)[(ni)], (etoa)[(ni)])

extern vlib_node_registration_t mrvl_pp2_input_node;

/* format.c */
format_function_t format_mrvl_pp2_input_trace;
format_function_t format_mrvl_pp2_interface;
format_function_t format_mrvl_pp2_interface_name;


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

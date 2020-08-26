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
#ifndef __included_etfs_fragment_h__
#define __included_etfs_fragment_h__

#include <vlib/vlib.h>

/* swiped from iptfs */
#define vec_shift(v, n)       \
  do                          \
    {                         \
      if ((n) == vec_len (v)) \
        vec_reset_length (v); \
      else                    \
        vec_delete (v, n, 0); \
    }                         \
  while (0)

/*
 * ETFS consolidated received fragment. This header refers to a fragment
 * that could possibly be a merged set of adjacent fragments. The buffer
 * index could be a chain.
 */
typedef struct {
    u32		seq_initial;
    u32		seq_final;
    u32		bi_frag;

    bool	have_first_frag : 1;
    bool	have_last_frag : 1;
} etfs_frag_t;


extern void
etfs_receive_fragment(
    vlib_main_t			*vm,
    state_decap_flow_v2_t	*df,
    u32				bi,
    bool			initial,
    bool			final,
    bool			express,
    u32				seqnum,
    u32				**send,
    u32				**drop);

#endif /* __included_iptfs_fragment_h__ */

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

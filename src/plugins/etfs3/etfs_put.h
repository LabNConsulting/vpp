/*
 * May 24 2019, Christian Hopps <chopps@labn.net>
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

/*
 * vlib_put_* macros from ipsec_iptfs.h
 */

#define vlib_node_increment_counter_p(vm, node, cnt, eto, to)         \
  do                                                                  \
    {                                                                 \
      vlib_node_increment_counter ((vm), (node)->node_index, (cnt),   \
				   VLIB_FRAME_SIZE - ((eto) - (to))); \
    }                                                                 \
  while (0)

#define vlib_put_next_frame_with_cnt(vm, node, ni, to, eto, cnt)              \
  do                                                                          \
    {                                                                         \
      if ((to))                                                               \
	{                                                                     \
	  vlib_put_next_frame ((vm), (node), (ni), (eto) - (to));             \
	  if (cnt != ~0)                                                      \
	    vlib_node_increment_counter_p ((vm), (node), (cnt), (eto), (to)); \
	}                                                                     \
    }                                                                         \
  while (0)

#define vlib_put_get_next_frame(vm, node, ni, to, eto, cnt)          \
  do                                                                 \
    {                                                                \
      /* Put the frame if it is full */                              \
      if ((to) && (eto) != (to))                                     \
	;                                                            \
      else                                                           \
	{                                                            \
	  vlib_put_next_frame_with_cnt (vm, node, ni, to, eto, cnt); \
	  vlib_get_next_frame_p ((vm), (node), (ni), (to), (eto));   \
	}                                                            \
    }                                                                \
  while (0)

#define vlib_put_get_next_frame_a(vm, node, ni, toa, etoa) \
  vlib_put_get_next_frame (vm, node, ni, (toa)[(ni)], (etoa)[(ni)], ~0)



/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

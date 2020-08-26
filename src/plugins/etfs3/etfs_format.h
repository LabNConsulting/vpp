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
#ifndef __included_etfs_format_h__
#define __included_etfs_format_h__

#include <vlib/vlib.h>

/*
 * MPPCI Component info for tracing
 */
typedef struct {
    u8			type;
    bool		flag_trailing_pad : 1;
    bool		flag_initial : 1;
    bool		flag_final : 1;
    bool		flag_express : 1;
    bool		flag_parse_error : 1;
    u16			following_length;
    u32			fragment_number;
    ethernet_header_t	hdr;
    u16			hdrlen;	/* not needed? */
    u16			offset;
    char		error_string[10+1];
} etfs_mc_trace_t;

typedef struct {
    ethernet_header_t	hdr;
    bool		flag_invalid : 1;
    bool		flag_received : 1;
    bool		flag_transmit : 1;
    bool		flag_user : 1;		/* is a user frame, not MPPDU */
    u32			sw_if_index;
    u32			buffer_length;
    u32			n_mc;
    etfs_mc_trace_t	mc[0];
} etfs_mppdu_trace_t;


extern void
etfs_trace_mppdu(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_buffer_t	*b0,
    u16			generation,
    bool		transmit);

extern void
etfs_trace_updu(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_buffer_t	*b0,
    bool		transmit);

extern u8 *
format_etfs_mppdu_mc_type(u8 *s, va_list *args);

extern u8 *
format_etfs_mppdu_mc(u8 *s, va_list *args);

extern u8 *
format_etfs_mppdu_trace(u8 *s, va_list *args);

#endif /* __included_etfs_format_h__ */

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

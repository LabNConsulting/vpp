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
#include <stddef.h>
#include <vppinfra/types.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <plugins/etfs3/etfs3.h>
#include <plugins/etfs3/etfs_format.h>

/*
 * returns true if more blocks to parse
 */
static bool
_get_next_header(
    vlib_main_t				*vm,
    datablock_reassembly_cursor_t	*scurs,
    etfs_mc_trace_t			*mct)
{
    u8	byte1;
    u16	remaining;

    clib_memset(mct, 0, sizeof(*mct));

    mct->offset = b_offset_of(scurs);

    /* upper bits of first byte */
    if (b_get_u8(scurs, &byte1)) {
	/* parse error/malformed packet */
	mct->flag_parse_error = true;
	snprintf(mct->error_string, sizeof(mct->error_string), "1");
	return false;
    }
    mct->type = ETFS_MPPCI_GET_ID(byte1);

    /* first two bytes except upper bits */
    if (b_get_u16(vm, scurs, &mct->following_length)) {
	/* parse error/malformed packet */
	mct->flag_parse_error = true;
	snprintf(mct->error_string, sizeof(mct->error_string), "2");
	return false;
    }
    mct->following_length &= ~ETFS_MPPCI_ID_MASK16;

    /* trailing pad */
    if ((mct->type == ETFS_MPPCI_ID_FRAME) &&
	(mct->following_length == 0)) {

	mct->flag_trailing_pad = true;
	return false;
    }
    if (b_cursor_advance(vm, scurs, 2)) {
	/* parse error/malformed packet */
	mct->flag_parse_error = true;
	snprintf(mct->error_string, sizeof(mct->error_string), "3");
	return false;
    }

    remaining = mct->following_length;

    if (mct->type == ETFS_MPPCI_ID_FRAME) {
	mct->hdrlen =
	    b_get_bytes(vm, scurs, (char *)&mct->hdr,
		sizeof(ethernet_header_t));
    }

    if (mct->type == ETFS_MPPCI_ID_FRAGMENT) {
	u8	flags;

	if (b_get_u8(scurs, &flags)) {
	    /* parse error/malformed packet */
	    mct->flag_parse_error = true;
	    snprintf(mct->error_string, sizeof(mct->error_string), "4");
	    return false;
	}
	if (flags & ETFS_MPPCI_FRAG_INITIAL)
	    mct->flag_initial = true;
	if (flags & ETFS_MPPCI_FRAG_FINAL)
	    mct->flag_final = true;
	if (flags & ETFS_MPPCI_FRAG_EXPRESS)
	    mct->flag_express = true;

	if (b_get_u32(vm, scurs, &mct->fragment_number)) {
	    /* parse error/malformed packet */
	    mct->flag_parse_error = true;
	    snprintf(mct->error_string, sizeof(mct->error_string), "5");
	    return false;
	}
	mct->fragment_number &= 0xffffff;

	if (b_cursor_advance(vm, scurs, 4)) {
	    /* parse error/malformed packet */
	    mct->flag_parse_error = true;
	    snprintf(mct->error_string, sizeof(mct->error_string), "6");
	    return false;
	}
	remaining -= 4;
	if (mct->flag_initial &&
	    (remaining >=  sizeof(ethernet_header_t))) {

	    mct->hdrlen = b_get_bytes(vm, scurs, (char *)&mct->hdr,
		sizeof(ethernet_header_t));
	}
    }

    if (b_bytes_available(vm, scurs) == remaining) {
	/* normal case: we're done */
	return false;
    }

    if (b_cursor_advance(vm, scurs, remaining)) {
	/* parse error/malformed packet */
	mct->flag_parse_error = true;
	snprintf(mct->error_string, sizeof(mct->error_string),
	    "7:%hu", remaining);
	return false;
    }

    if (b_bytes_available(vm, scurs) > 2)
	return true;

    return false;
}

/* TBD vlib_buffer_get_current() is wrong for indirect buffers */
void
etfs_trace_mppdu(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_buffer_t	*b0,
    u16			generation,
    bool		transmit)
{
    bool				more = false;
    datablock_reassembly_cursor_t	curs;
    etfs_mc_trace_t			*pMc, *mc = NULL;
    bool				invalid = false;
    etfs_mppdu_trace_t			*t;

    /*
     * For transmit, start of buffer is at the start of the outer
     * ethernet header.
     *
     * But for receive, start of buffer is after the outer ethernet header,
     * at the start of the payload.
     */

    /* Assume ethernet header is contiguous in first buffer */
    if (b_cursor_set(vm, b0, &curs, transmit? sizeof(ethernet_header_t): 0)) {
	invalid = true;
	goto save_trace;
    }

    if (b_bytes_available(vm, &curs) < 2) {
	invalid = true;
	goto save_trace;
    }

    /*
     * process mppdu components
     */
    do {
	vec_add2(mc, pMc, 1);
	more = _get_next_header(vm, &curs, pMc);
    } while(more);

save_trace:

    /*
     * this probably allocates sizeof(etfs_mc_trace_t) more than we
     * need since one etfs_mc_trace_t is already included in
     * etfs_mppdu_trace_t.
     */
    t = vlib_add_trace(vm, node, b0,
	sizeof (*t) + sizeof(etfs_mc_trace_t) * vec_len(mc));

    if (transmit) {
	t->flag_transmit = true;
	t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
    } else {
	t->flag_received = true;
	t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
    }
    t->buffer_length = vlib_buffer_length_in_chain(vm, b0);

    if (invalid) {
	t->flag_invalid = true;
	vec_free(mc);
	return;
    }
    if (transmit) {
	clib_memcpy_fast(&t->hdr, vlib_buffer_get_current(b0),
	    sizeof(ethernet_header_t));
    }
    t->n_mc = vec_len(mc);
    if (t->n_mc)
	clib_memcpy_fast(t->mc, mc, t->n_mc * sizeof(*mc));

    vec_free(mc);
}

u8 *
format_etfs_mppdu_mc_type(u8 *s, va_list *args)
{
#if 0
    CLIB_UNUSED (vlib_main_t *vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t *node) = va_arg(*args, vlib_node_t *);
#endif
    etfs_mc_trace_t *t = va_arg (*args, etfs_mc_trace_t *);

    const char	*ts = "??";

    switch (t->type) {
	case ETFS_MPPCI_ID_FRAGMENT:
	    ts = "FRAG";
	    break;
	case ETFS_MPPCI_ID_EXPLICIT_PAD:
	    ts = "EXPL PAD";
	    break;
	case ETFS_MPPCI_ID_FRAME:
	    if (t->flag_trailing_pad)
		ts = "TRAIL PAD";
	    else
		ts = "FRAME";
	    break;
    }
    s = format(s, "%s", ts);
    return s;
}

u8 *
format_etfs_mppdu_mc(u8 *s, va_list *args)
{
#if 0
    CLIB_UNUSED (vlib_main_t *vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t *node) = va_arg(*args, vlib_node_t *);
#endif

    etfs_mc_trace_t *t = va_arg (*args, etfs_mc_trace_t *);

    u32 indent = format_get_indent (s);

    s = format(s, "%Umc off %4u, type %U, fol len %u",
	format_white_space, indent,
	t->offset,
	format_etfs_mppdu_mc_type, t,
	t->following_length);

    if (t->flag_parse_error) {
	s = format(s, " !! etfs mppdu mc PARSE ERROR !! [%s] ", t->error_string);
    }

    if (t->flag_trailing_pad || t->type == ETFS_MPPCI_ID_EXPLICIT_PAD)
	return s;

    if (t->type == ETFS_MPPCI_ID_FRAGMENT) {
	s = format(s, " IF: %u, LF: %u, EX: %u, fn %u",
	    t->flag_initial, t->flag_final, t->flag_express,
	    t->fragment_number);
	if (t->flag_initial &&
	    (t->following_length >= 4 + sizeof(ethernet_header_t)))
	    goto have_eh;
	return s;
    }

have_eh:
    /*
     * have user frame ethernet header
     */
    s = format(s, "\n%U  dst %U, src %U, etype 0x%04x",
	format_white_space, indent,
	format_ethernet_address, t->hdr.dst_address,
	format_ethernet_address, t->hdr.src_address,
	clib_net_to_host_u16(t->hdr.type));
    return s;
}

u8 *
format_etfs_mppdu_trace(u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t *vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t *node) = va_arg(*args, vlib_node_t *);

    etfs_mppdu_trace_t *t = va_arg (*args, etfs_mppdu_trace_t *);

    if (t->flag_invalid) {
	s = format(s,
	    "etfs mppdu: %cx sw_if_index %u, totlen %u, contents invalid",
	    (t->flag_transmit? 't': 'r'),
	    t->sw_if_index,
	    t->buffer_length);
	return s;
    }

    if (t->flag_transmit) {
	/* transmit pkts have outer ether header info */
	s = format(s, "etfs %s: %cx sw_if_index %u, totlen %u, dst %U, src %U"
	    " n_mc %u",
	    (t->flag_user? "user frame": "mppdu"),
	    't',
	    t->sw_if_index,
	    t->buffer_length,
	    format_ethernet_address, t->hdr.dst_address,
	    format_ethernet_address, t->hdr.src_address,
	    t->n_mc);
    } else {
	/* no outer ethernet header info for receive */
	s = format(s, "etfs %s: %cx sw_if_index %u, totlen %u"
	    " n_mc %u",
	    (t->flag_user? "user frame": "mppdu"),
	    'r',
	    t->sw_if_index,
	    t->buffer_length,
	    t->n_mc);
    }

    for (u32 i = 0; i < t->n_mc; ++i) {
	s = format(s, "\n  %U", format_etfs_mppdu_mc, t->mc + i);
    }

    s = format(s, "\n");

    return s;
}

/* TBD vlib_buffer_get_current() is wrong for indirect buffers */
/* trace user frames */
void
etfs_trace_updu(
    vlib_main_t		*vm,
    vlib_node_runtime_t	*node,
    vlib_buffer_t	*b0,
    bool		transmit)
{
    etfs_mppdu_trace_t			*t;

    t = vlib_add_trace(vm, node, b0, sizeof (*t));

    if (transmit) {
	t->flag_transmit = true;
	t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
    } else {
	t->flag_received = true;
	t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
    }
    t->flag_user = true;
    t->buffer_length = vlib_buffer_length_in_chain(vm, b0);

    clib_memcpy_fast(&t->hdr, vlib_buffer_get_current(b0),
	sizeof(ethernet_header_t));
}


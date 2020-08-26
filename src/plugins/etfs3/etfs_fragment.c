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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/dpo/dpo.h>	/* INDEX_INVALID */
#include <vppinfra/error.h>

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

#include <etfs3/etfs3.h>
#include <etfs3/etfs_encap.h>
#include <etfs3/etfs_fragment.h>

/*
 * For dealing with 24-bit sequence numbers
 */
#define SIGNEXT24_32(x) ((((i32)(x) + 0x00800000) & 0x00ffffff) - 0x00800000)
#define SEQCMP24_32(a,b) ( (i32)( SIGNEXT24_32(a) - SIGNEXT24_32(b) ) )

/*
 * assemble buffers from idx_first to idx_last into a single packet
 */
static inline u32
_assemble_fragments(
    vlib_main_t			*vm,
    struct etfs_decap_reasm	*pR,
    u16				idx_first,
    u16				idx_last,
    u32				*total_length,
    u32				**drop)
{
    u32			bi_userframe;
    vlib_buffer_t	*b;
    vlib_buffer_t	*seg_prev = NULL;
    vlib_buffer_t	*seg_first = NULL;
    u16			i;

    *total_length = 0;

    bi_userframe = pR->win[idx_first].bi;

    ASSERT(idx_first <= idx_last);

    for (i = idx_first; i <= idx_last; ++i) {
	ASSERT(pR->win[i].flag_valid);
	b = vlib_get_buffer(vm, pR->win[i].bi);
	pR->win[i].flag_valid = false;
#if ETFS_ENABLE_BUFFER_NOTES
	vlib_buffer_note_add(b, ">%s", __func__);
#endif
	if (seg_prev) {
	    seg_prev->next_buffer = pR->win[i].bi;
	    seg_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	} else {
	    seg_first = b;
	    b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	}
	*total_length += b->current_length;
	seg_prev = b;
    }
#if ! ETFS_TX_MULTISEG_INDIRECT
#define AVERYBIGMTU 100000
    if (b_chain_compact(vm, &bi_userframe, AVERYBIGMTU)) {
	vec_add1(*drop, bi_userframe);
	return (u32)~0;
    }
    seg_first = vlib_get_buffer(vm, bi_userframe);
#endif
    ASSERT(*total_length == vlib_buffer_length_in_chain(vm, seg_first));
    ASSERT(pR->win[idx_first].flag_valid == false);
    return bi_userframe;
}

/*
 * could result in multiple reassembled packets
 */
static inline void
_reassemble(
    vlib_main_t			*vm,
    u32				if_index_tx,
    struct etfs_decap_reasm	*pR,
    u16				flow_index,
    u32				**send,
    u32				**drop)
{
    u16				i;
    u16				veclen = vec_len(pR->win);

    ASSERT(veclen);

    /*
     * Head-of-line must be first-fragment
     *
     * If we have head-of-line but it is not first, we know we will never
     * be able to reassemble the packet that HOL belongs to. So drop all
     * fragments until we hit a hole or initial fragment.
     */
    for (i = 0;
	pR->win[i].flag_valid && !pR->win[i].flag_initial &&
	    (i < veclen);
	++i) {

	ETFS_DEBUG(REASM_REASM, 3, "discard seq %u, valid %u, IF %u, FF %u\n",
		pR->win[i].sequence,
		pR->win[i].flag_valid,
		pR->win[i].flag_initial,
		pR->win[i].flag_final);

	/* discard */
	vec_add1(*drop, pR->win[i].bi);
	pR->win[i].flag_valid = false;
	pR->win[i].bi = ~0u;
	ETFS_DECAP_SCTR_INC(FRAG, DEQUEUED_DROP_NOTHOL, flow_index);
    }

    if (i) {
	ETFS_DEBUG(REASM_REASM, 1, "discarding %u previous of %u", i, veclen);

	vec_shift(pR->win, i);
	ASSERT(pR->nextidx >= i);
	pR->nextidx -= i;

	if (i == veclen)
	    return;

	veclen -= i;
    }

    /*
     * If slot is empty, we are still waiting for it and can't reassemble.
     */
    if (!pR->win[0].flag_valid) {
	ETFS_DEBUG(REASM_REASM, 1, "first slot empty, return");
	return;
    }

    /*
     * Must have head-of-line (otherwise, we are still waiting for it)
     */
    ASSERT(pR->win[0].flag_initial);

    /*
     * Do we have a complete packet?
     */
    bool	completed;
    do {
	completed = false;
	for (i = 0; (i < veclen) && pR->win[i].flag_valid; ++i) {
	    if (pR->win[i].flag_final) {

		u32	reassembled_length;

		ETFS_DEBUG(REASM_REASM, 1, "complete: 0->%u\n", i);

		/* got one */
		u32 bi = _assemble_fragments(vm, pR, 0, i, &reassembled_length, drop);
		vec_shift(pR->win, i+1);
		ASSERT(pR->nextidx >= (i+1));
		pR->nextidx -= (i+1);
		veclen -= (i+1);
		if (bi != (u32)~0) {
		    vec_add1(*send, bi);
		    vlib_buffer_t *b = vlib_get_buffer(vm, bi);
		    vnet_buffer(b)->sw_if_index[VLIB_TX] = if_index_tx;
		    ETFS_DECAP_CCTR_ADD(FRAG, DEQUEUED_ASSEMBLED,
			flow_index,  i+1, reassembled_length);
		    ETFS_DECAP_CCTR_INC(FRAG, PKT_SENT_ASM,
			flow_index, reassembled_length);
		} else {
		    ETFS_DECAP_CCTR_ADD(FRAG, DEQUEUED_DROP_ASM_NOMEM,
			flow_index,  i+1, reassembled_length);
		    ETFS_DECAP_CCTR_INC(FRAG, PKT_DROP_ASM_NOMEM,
			flow_index, reassembled_length);
		}
		completed = true;
		break;
	    }
	    if (i && pR->win[i].flag_initial) {
		/*
		 * Oops, encoding error by sender. We got an initial
		 * fragment for the next user packet before the final
		 * fragment of the current one.
		 *
		 * Discard previous fragments and restart assembly attempt
		 */
		ETFS_DECAP_SCTR_ADD(FRAG, DEQUEUED_DROP_TAILLESS, flow_index,
		    i);
		ETFS_DEBUG(REASM_REASM, 1,
		    "discarding %u previous tailless of %u", i, veclen);
		for (uint j = 0; j < i; ++j) {
		    vec_add1(*drop, pR->win[j].bi);
		    pR->win[j].flag_valid = false;
		    pR->win[j].bi = ~0u;
		}
		vec_shift(pR->win, i);
		ASSERT(pR->nextidx >= i);
		pR->nextidx -= i;
		veclen -= i;
		completed = true; /* keep outer loop going */
		break;
	    }
	}
    } while (completed);
}

void
etfs_receive_fragment(
    vlib_main_t			*vm,
    state_decap_flow_v2_t	*df,
    u32				new_bi,
    bool			initial,
    bool			final,
    bool			express,
    u32				seqnum,
    u32				**send,
    u32				**drop)
{
    struct etfs_decap_reasm	*pR;
    etfs_fragment_stream_type_t	st = (express? EXPRESS: NORMAL);

    pR = &df->reasm[st];

    ETFS_DEBUG(REASM_RX, 1,
	"seq %u, want nextseq %u, nextidx %u, IF:%u, FF %u\n",
	seqnum, pR->nextseq, pR->nextidx, initial, final);

    if (PREDICT_TRUE(seqnum == pR->nextseq)) {
	ETFS_DECAP_SCTR_INC(FRAG, SEQ_EXPECTED, df->config.index);

	/*
	 * Place fragment in its slot
	 */
	vec_validate_init_empty(pR->win, pR->nextidx, (etfs_reasm_t){0});
	ASSERT(!pR->win[pR->nextidx].flag_valid);
	pR->win[pR->nextidx].sequence = seqnum;
	pR->win[pR->nextidx].bi = new_bi;
	pR->win[pR->nextidx].flag_valid = true;
	pR->win[pR->nextidx].flag_initial = initial;
	pR->win[pR->nextidx].flag_final = final;

	/*
	 * find next open slot and adjust nextidx, nextseq
	 */
	while ((pR->nextidx < vec_len(pR->win)) &&
	    (pR->win[pR->nextidx].flag_valid)) {

	    ++pR->nextseq;
	    ++pR->nextidx;
	}
	pR->nextseq &= 0xffffff;	/* wrap 24 bits */

	ETFS_DEBUG(REASM_RX, 3, "now nextseq %u, nextidx %u\n",
	    pR->nextseq, pR->nextidx);

	/*
	 * attempt reassembly of all leading complete packets
	 */
	_reassemble(vm, df->config.if_index_tx, pR, df->config.index, send, drop);

	ETFS_DEBUG(REASM_RX, 3, "reassemble attempt returned\n");

	return;
    }

    /*
     * compute 24bit wrapped difference (similar to IP seq comparison)
     * TBD verify that this macro is correct
     */
    i32	seqdiff = SEQCMP24_32(seqnum, pR->nextseq);

    if (seqdiff < 0) {
	/*
	 * discard
	 *
	 * This fragment is older than our oldest empty slot (although
	 * it might still be in the window if it is a duplicate).
	 */
	ETFS_DECAP_SCTR_INC(FRAG, SEQ_OLD_DROP, df->config.index);
	vec_add1(*drop, new_bi);
	return;
    }

    /*
     * Reaching here means the fragment's sequence number is above
     * our first empty slot.
     *
     * If it is within the window, then just place it in the proper slot.
     *
     * If it is beyond the window, then shift the window ahead,
     * while assembling complete fragment sets into packets and
     * discarding other fragments no longer in the window.
     */

    /*
     * NB we measure window from oldest unassembled fragment
     */
    u32	newidx = seqdiff + pR->nextidx;

    if (newidx < df->config.maxwin) {
	/*
	 * in window
	 */

	ETFS_DECAP_SCTR_INC(FRAG, SEQ_IN_WIN, df->config.index);

	vec_validate_init_empty(pR->win, newidx, (etfs_reasm_t){0});

	if (pR->win[newidx].flag_valid) {
	    /*
	     * Duplicate sequence number
	     */
	    ETFS_DECAP_SCTR_INC(FRAG, SEQ_IN_WIN_DUP_DROP, df->config.index);
	    vec_add1(*drop, new_bi);
	    return;
	}

	pR->win[newidx].sequence = seqnum;
	pR->win[newidx].bi = new_bi;
	pR->win[newidx].flag_valid = true;
	pR->win[newidx].flag_initial = initial;
	pR->win[newidx].flag_final = final;

	return;
    }

    ETFS_DECAP_SCTR_INC(FRAG, SEQ_BEYOND_WIN, df->config.index);

    /*
     * Beyond window. Shift it.
     *
     * For fragments shifted out of the window: reassemble any fragment
     * sets that make a complete packet and discard the rest.
     * Any fragment set with a "first fragment" no longer in the window
     * is eligible for reassembly, even if it extends into the window.
     *
     * Although normally we don't reassemble a packet until fragments
     * prior to it have been reassembled (we do our best to keep things
     * in order), once we are committed to shifting the window, it is
     * better to reassemble than discard.
     */
    u32	shift = newidx - df->config.maxwin;

    u16 i, j;
    u32 veclen = vec_len(pR->win);

    for (i = 0; (i < shift) && (i < veclen); ++i) {
	if (pR->win[i].flag_valid) {
	    if (!pR->win[i].flag_initial) {
		vec_add1(*drop, pR->win[i].bi);
		pR->win[i].flag_valid = false;
		pR->win[i].bi = ~0u;
		ETFS_DECAP_SCTR_INC(FRAG, DEQUEUED_DROP_SHIFT1, df->config.index);
	    } else {
		/*
		 * iterate until we reach an empty slot
		 * */
		for (j = i;
		    (j < veclen) &&
			pR->win[j].flag_valid &&
			!pR->win[j].flag_final;
		    ++j);
		if ((j >= veclen) || !pR->win[j].flag_valid) {
		    /* didn't get valid final fragment */
		    vec_add1(*drop, pR->win[i].bi);
		    pR->win[i].flag_valid = false;
		    pR->win[i].bi = ~0u;
		    ETFS_DECAP_SCTR_INC(FRAG, DEQUEUED_DROP_SHIFT2, df->config.index);
		    /* continue outer loop to drop rest of frags */
		} else {
		    u32	reassembled_length;
		    u32	bi;

		    /* got contiguous set of fragments */
		    bi = _assemble_fragments(vm, pR, i, j, &reassembled_length, drop);
		    if (bi != (u32)~0) {
			ETFS_DECAP_CCTR_ADD(FRAG, DEQUEUED_ASSEMBLED,
			    df->config.index, j-i+1, reassembled_length);
			vlib_buffer_t *b = vlib_get_buffer(vm, bi);
			vnet_buffer(b)->sw_if_index[VLIB_TX] =
			    df->config.if_index_tx;
			vec_add1(*send, bi);
			ETFS_DECAP_CCTR_INC(FRAG, PKT_SENT_ASM,
			    df->config.index, reassembled_length);
		    } else {
			ETFS_DECAP_CCTR_ADD(FRAG, DEQUEUED_DROP_ASM_NOMEM,
			    df->config.index,  j-i+1, reassembled_length);
			ETFS_DECAP_CCTR_INC(FRAG, PKT_DROP_ASM_NOMEM,
			    df->config.index, reassembled_length);
		    }
		    i = j;
		}
	    }
	}
    }

    /*
     * At this point, i could be more than "shift" because the last
     * reassembled packet could extend into the space we didn't need
     * to shift out.
     */

    vec_shift(pR->win, clib_min(i, veclen));

    ASSERT(newidx >= i);

    newidx -= i;

    /*
     * Place fragment in its slot
     */
    vec_validate_init_empty(pR->win, newidx, (etfs_reasm_t){0});
    ASSERT(!pR->win[newidx].flag_valid);
    pR->win[newidx].sequence = seqnum;
    pR->win[newidx].bi = new_bi;
    pR->win[newidx].flag_valid = true;
    pR->win[newidx].flag_initial = initial;
    pR->win[newidx].flag_final = final;

    /*
     * find first empty slot
     */
    for (i = 0; i < vec_len(pR->win); ++i)
	if (!pR->win[i].flag_valid)
	    break;

    /*
     * Calculate sequence number of the empty slot we just found.
     *
     * We know this about the new fragment:
     *	seqnum	- 24-bit sequence number
     *	newidx	- vector index
     *
     * We also know the index of the first open slot: i
     *
     * So the signed quantity (i - newidx) means "how much higher is
     * the open slot than the new fragment." Note that since it is
     * possible that the new fragment is higher than the first open slot,
     * this number could be negative.
     *
     * So the open slot's sequence number is also (i - newidx) higher
     * than "seqnum". Thus:
     *
     * nextseq = seqnum + i - newidx
     *
     * Since these are signed calculations, we should sign-extend the
     * 24-bit values to 32 bits and then mask back to 24 at the end.
     *
     * Further note that the empty slot does not actually need to exist
     * in the fragment vector. We will extend the vector as needed when
     * it arrives.
     */

    pR->nextseq = 
	(SIGNEXT24_32(seqnum) + i - SIGNEXT24_32(newidx)) & 0x00ffffff;
    pR->nextidx = i;

    /*
     * If first slot is not empty, there is a chance there could be
     * a complete set of fragments.
     */
    if (pR->win[0].flag_valid) {
	/* ASSERT(pR->win[0].flag_initial); */ /* Not valid assumption? */
	/* attempt reasembly */
	_reassemble(vm, df->config.if_index_tx, pR, df->config.index, send, drop);
    }
}

/*
 * TBD we also need some sort of serialized (on same thread) timeout
 * mechanism to discard old fragments.
 */

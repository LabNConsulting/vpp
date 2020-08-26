/*
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

#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
    /*
     * tunnel packets have been initialized with a 6-byte explicit
     * pad (2B header, 4B pad) for debugging. Don't send if this is
     * the only payload.
     */
#define ETFS_INPROG_HAS_PAYLOAD(b, ef) 	\
    ((b)->current_length > (ef)->config.ether_header_len + 6)
#else
#define ETFS_INPROG_HAS_PAYLOAD(b, ef) 	\
    ((b)->current_length > (ef)->config.ether_header_len)
#endif

/*
 * If inprogress buffer contains any user frame or fragment, pad the rest,
 * detach from ef structure, and return true.
 * Otherwise leave it alone and return false.
 */
static inline bool
encap_finish_inprogress(
    vlib_main_t			*vm,		/* IN */
    struct state_encap_flow_v2	*ef,		/* IN */
    u32				*pBi,		/* OUT */
    u32				*uf_bytes,	/* OUT */
    u32				*nsegs)		/* OUT */
{
    vlib_buffer_t	*b_inprogress;

    if (ef->encap.bi_inprogress == ~0u)
	return false;

    /* nothing in the in-progress buffer */
    if (ef->encap.space_avail == ef->config.framesize)
	return false;

    b_inprogress = vlib_get_buffer(vm, ef->encap.bi_inprogress);

    if (!ETFS_INPROG_HAS_PAYLOAD(b_inprogress, ef))
	return false;

#if ETFS_DEBUG_FFC_IN_EXPLICIT_PAD
    /*
     * Insert count of full frames in explicit pad at start
     * MPPCI header is 2 bytes. 4 byte area, 1 byte value goes
     * at end (highest address, thus the 3)
     */
    {
	u8 *p;

	p = vlib_buffer_get_current(b_inprogress) +
	    ef->config.ether_header_len + 2 + 3;

	*p = ef->encap.ffc_inprogress & 0xff;

	ef->encap.ffc_inprogress = 0;
    }
#endif

    /*
     * pad the end as needed
     */
    if (ef->encap.space_avail) {

#if ETFS_ENCAP_ALLOC_FROM_HEAP
	char *p = vlib_buffer_put_uninit(b_inprogress, ef->encap.space_avail);
	clib_memset(p, 0, ef->encap.space_avail);
#else
	/*
	 * tunnel frames have been allocated from the encap zpool, which has
	 * already pre-zeroed the contents.
	 */
	(void)vlib_buffer_put_uninit(b_inprogress, ef->encap.space_avail);
#endif
    }

    *pBi = ef->encap.bi_inprogress;
    *uf_bytes = ef->encap.uf_bytes;
    *nsegs = ef->encap.nsegs_inprogress;

    /*
     * long-term plan is to produce only direct/single-segment packets
     * and to remove calls to B_CHAIN_COMPACT() in the etfs encap path
     */
    ASSERT(*nsegs == 1);

    ef->encap.bi_inprogress = ~0u;
    ef->encap.space_avail = ef->config.framesize;
    ef->encap.uf_bytes = 0;

    return true;
}


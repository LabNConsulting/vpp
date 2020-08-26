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
#include <vnet/macsec/macsec.h>
#include <vnet/macsec/macsec_sa.h>
#include <vppinfra/error.h>

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

#include <vnet/l2/l2_xcrw.h>

#include <etfs3/etfs3.h>


#define ETFS_RX_INTERFACE_REDIRECT	0	/* 1=old style, 0=l2xc */

static void
etfs_set_flow_index(etfs_flow_type_t flowtype, u16 index, void *flow)
{
    ASSERT(vec_len(etfs3_main.idx_flow[flowtype]) > index);
    etfs3_main.idx_flow[flowtype][index] = flow;
}

/*
 * deallocate slot if it matches flow
 */
static void
etfs_free_flow_index(etfs_flow_type_t flowtype, u16 index, void *flow)
{
    if (index >= vec_len(etfs3_main.idx_flow[flowtype]))
	return;
    if (etfs3_main.idx_flow[flowtype][index] == flow)
	etfs_set_flow_index(flowtype, index, (void *)0);
}

static int
etfs_alloc_flow_index(etfs_flow_type_t flowtype, u16 *index)
{
    uint	idx;

    /*
     * make sure we have defined a max less then the max of the
     * index type we return.
     */
    ASSERT(ETFS_MAX_FLOWS == (ETFS_MAX_FLOWS & 0xffff));

    /*
     * find unallocated entry
     */
    idx = vec_search(etfs3_main.idx_flow[flowtype], (void *)0);

    if (idx != ~0u)
	goto found;

    /*
     * find abandoned entry
     */
    idx = vec_search(etfs3_main.idx_flow[flowtype], (void *)1);

    if (idx != ~0u)
	goto found;

    if (vec_len(etfs3_main.idx_flow[flowtype]) >= ETFS_MAX_FLOWS)
	return -1;

    /*
     * make new entry
     */
    void **p;
    vec_add2(etfs3_main.idx_flow[flowtype], p, 1);
    idx = p - etfs3_main.idx_flow[flowtype];

found:
    etfs_set_flow_index(flowtype, idx, (void *)1);
    *index = idx & 0xffff;
    return 0;
}

state_encap_flow_v2_t *
encap_flow_get(
    u16			encap_rxport)	/* rx port of flow to look up */
{
    /*
     * Look up encap state for the flow based on received interface.
     * See vnet/l2/l2_fib.h'l2fib_valid_swif_seq_num for example.
     */
    BVT (clib_bihash_kv) kv;
    kv.key = encap_rxport;
    if (BV (clib_bihash_search)(&etfs3_main.encap_flow_table, &kv, &kv)) {
	return NULL;
    }
    return (state_encap_flow_v2_t *)(kv.value);
}

state_decap_flow_v2_t *
decap_flow_get(
    u16		decap_rxport,	/* rx port of flow to look up */
    bool	encrypted)	/* selected encrypted/plain flow on this port */
{
    BVT (clib_bihash_kv)	search;
    BVT (clib_bihash_kv)	result;
    BVT(clib_bihash)		*pDecapFlowTable;

    pDecapFlowTable = encrypted?
	&etfs3_main.decap_flow_table_macsec:
	&etfs3_main.decap_flow_table;

    search.key = decap_rxport;
    if (!BV(clib_bihash_search)(pDecapFlowTable, &search, &result))
	return (state_decap_flow_v2_t *)result.value;

    return NULL;
}

/*
 * Only dpdk interfaces can transmit stealth indirect buffers. Other
 * interfaces will send the wrong data and will leak indirect buffers.
 */
static bool
is_dpdk_interface(u32 sw_if_index)
{
    vnet_main_t		*vnm;
    vnet_hw_interface_t	*hwi;
    vnet_device_class_t	*device_class;

    vnm = vnet_get_main();
    hwi = vnet_get_sup_hw_interface(vnm, sw_if_index);
    device_class = vnet_get_device_class(vnm, hwi->dev_class_index);

    if (!strcmp("dpdk", device_class->name))
	return true;

    return false;
}

static void
etfs_clear_flow_counters(etfs_flow_type_t flowtype, u16 index)
{
    switch (flowtype) {
    case ENCAP:
	/*
	 * pass the largest possible index to vlib_validate_simple_counter,
	 * not the number of elements.
	 */
	for (uint i = 0; i < ETFS_ENCAP_SCTR_N_COUNTERS; ++i) {
	    vlib_validate_simple_counter(&etfs3_main.encap_scm[i], index);
	    vlib_zero_simple_counter(&etfs3_main.encap_scm[i], index);
	}
	for (uint i = 0; i < ETFS_ENCAP_CCTR_N_COUNTERS; ++i) {
	    vlib_validate_combined_counter(&etfs3_main.encap_ccm[i], index);
	    vlib_zero_combined_counter(&etfs3_main.encap_ccm[i], index);
	}
	break;

    case DECAP:
	for (uint i = 0; i < ETFS_DECAP_SCTR_N_COUNTERS; ++i) {
	    vlib_validate_simple_counter(&etfs3_main.decap_scm[i], index);
	    vlib_zero_simple_counter(&etfs3_main.decap_scm[i], index);
	}
	for (uint i = 0; i < ETFS_DECAP_CCTR_N_COUNTERS; ++i) {
	    vlib_validate_combined_counter(&etfs3_main.decap_ccm[i], index);
	    vlib_zero_combined_counter(&etfs3_main.decap_ccm[i], index);
	}
	break;

    default:
	ASSERT(0);
    }
}

/*
 * Release dynamically-allocated parts of encap flow structure and
 * then delete it
 */
static void
_ef_cleanup(state_encap_flow_v2_t *ef)
{
    vlib_main_t	*vm = vlib_get_main();

    if (ef->allocated.parent_flow_table_entry) {
	BVT (clib_bihash_kv)	search;
	search.key = ef->config.if_index_rx;

	clib_spinlock_lock(&etfs3_main.encap_flow_table_lock);
	BV(clib_bihash_add_del)(&etfs3_main.encap_flow_table, &search, 0 /*del*/);
	clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);
    }

    etfs_free_flow_index(ENCAP, ef->config.index, ef);

    if (ef->allocated.macsec_sa) {
        macsec_sa_delete(ef->config.ipsec_sa_index);
    }

    if (ef->allocated.output_zpool)
	etfs_zpool_free(vm, ef->output.zpool);

    if (ef->allocated.encap_to_pacer_q)
	iptfs_bufq_free(&ef->encap.pacer_queue);

#if ETFS_ENABLE_ELOG
    if (ef->allocated.encap_pacer_track_name)
	vec_free(ef->encap.pacer_track.name);

    if (ef->allocated.encap_zpool_track_name)
	vec_free(ef->encap.zpool_track.name);

    if (ef->allocated.encap_error_track_name)
	vec_free(ef->encap.error_track.name);

    if (ef->allocated.output_output_track_name)
	vec_free(ef->output.output_track.name);

    if (ef->allocated.output_zpool_track_name)
	vec_free(ef->output.zpool_track.name);

    if (ef->allocated.output_error_track_name)
	vec_free(ef->output.error_track.name);



    if (ef->allocated.encap_pacer_track_elog) {
	/* TBD - no method to free? */
    }

    if (ef->allocated.encap_zpool_track_elog) {
	/* TBD - no method to free? */
    }

    if (ef->allocated.encap_error_track_elog) {
	/* TBD - no method to free? */
    }

    if (ef->allocated.output_output_track_elog) {
	/* TBD - no method to free? */
    }

    if (ef->allocated.output_zpool_track_elog) {
	/* TBD - no method to free? */
    }

    if (ef->allocated.output_error_track_elog) {
	/* TBD - no method to free? */
    }

#endif /* ETFS_ENABLE_ELOG */

    if (ef->allocated.output_byte_counter_q)
	etfs_output_byte_counter_q_free(ef);

    clib_mem_free(ef);
}

static void
_df_cleanup(BVT(clib_bihash) *pDecapFlowTable, state_decap_flow_v2_t *df)
{
    vlib_main_t	*vm = vlib_get_main();

    if (df->allocated.parent_flow_table_entry) {
	BVT (clib_bihash_kv)	search;
	search.key = df->config.if_index_rx;

	clib_spinlock_lock(&etfs3_main.encap_flow_table_lock);
	BV(clib_bihash_add_del)(pDecapFlowTable, &search, 0 /*del*/);
	clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);
    }

    etfs_free_flow_index(DECAP, df->config.index, df);

    if (df->config.macsec_enabled) {
        macsec_sa_delete(df->config.ipsec_sa_index);
    }

    if (df->decoupler.rx) {
	b_free_bi_chain(vm, df->decoupler.rx, vec_len(df->decoupler.rx), __func__);
	vec_free(df->decoupler.rx);
    }
    /* free temp vectors */
    vec_free(df->decoupler.send);
    vec_free(df->decoupler.drop);

    if (df->reasm[NORMAL].win) {
	etfs_reasm_t	*pR;
	vec_foreach(pR, df->reasm[NORMAL].win) {
	    if (pR->flag_valid)
		b_free_bi_chain(vm, &pR->bi, 1, __func__);
	}
	vec_free(df->reasm[NORMAL].win);
    }
    if (df->reasm[EXPRESS].win) {
	etfs_reasm_t	*pR;
	vec_foreach(pR, df->reasm[EXPRESS].win) {
	    if (pR->flag_valid)
		b_free_bi_chain(vm, &pR->bi, 1, __func__);
	}
	vec_free(df->reasm[EXPRESS].win);
    }

    clib_mem_free(df);
}

int
etfs_encap_delete(vlib_main_t *vm, vnet_main_t *vnm, u32 rxport)
{
    /*
     * index on receive sw interface index
     */
    BVT (clib_bihash_kv)	kv;

    kv.key = rxport;
    if (BV(clib_bihash_search)(&etfs3_main.encap_flow_table, &kv, &kv)) {

	/* no matching rx interface */
	return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
    state_encap_flow_v2_t *ef = (state_encap_flow_v2_t *)(kv.value);

#if ETFS_RX_INTERFACE_REDIRECT
    int rc = vnet_hw_interface_rx_redirect_to_node(vnm,
	ef->config.if_hw_index_rx, ~0);
#else
    int rc = vnet_configure_l2_xcrw(vm, vnm, ef->config.if_sw_index_rx,
	~0u /* tx_fib_index */, NULL /* no rewriting */,
	~0u, 0 /* delete */);
#endif
    if (rc) {
	clib_error("can't disable redirection for rx interface "
	    "hw_index %u, sw_index %u\n",
	    ef->config.if_hw_index_rx,
	    ef->config.if_sw_index_rx);
    }

    etfs_clear_flow_counters(ENCAP, ef->config.index);

    etfs_thread_encap_unplace(ef);

    _ef_cleanup(ef);

    return 0;
}

int
etfs_decap_delete(u32 rxport, bool is_macsec)
{
    /*
     * index on receive sw interface index
     */
    BVT(clib_bihash)		*pDecapFlowTable;
    BVT (clib_bihash_kv)	kv;

    pDecapFlowTable = is_macsec?
	&etfs3_main.decap_flow_table_macsec:
	&etfs3_main.decap_flow_table;


    kv.key = rxport;
    if (BV(clib_bihash_search)(pDecapFlowTable, &kv, &kv)) {

	/* no matching rx interface */
	return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
    state_decap_flow_v2_t *df = (state_decap_flow_v2_t *)(kv.value);

    etfs_clear_flow_counters(DECAP, df->config.index);

    etfs_thread_decap_unplace(df);

    _df_cleanup(pDecapFlowTable, df);

    return 0;
}

/*
 * max u32 is about 4.3x10^9 (4G)
 *
 * max bits/msec using u32 is therefore 4.3x10^12 or 4300 Gb/s
 *
 * The calculation is
 *
 * bits-per-frame * core-ticks-per-second
 * -------------------------------------- = core-ticks-per-frame
 * bits-per-second
 *
 * equivalent to
 *
 * (bytes-per-frame * 8 * core-ticks-per-second) / (1000 * bits-per-msec)
 */
static u64
etfs_calc_tx_interval_cputicks(u32 framesize, u32 bits_per_msec)
{
    /* core-ticks/second is a large number (~ 5e9) */
    u64 ct = vlib_get_main()->clib_time.clocks_per_second;

    u64 val;

    /*
     * testing sometimes specifies very low rates: ensure we don't
     * try to divide by zero below.
     */
    if (!bits_per_msec)
	bits_per_msec= 1;

    /*
     * arrange calculation order to minimize chance of overflow
     * or loss of precision
     */
    val = ct / 1000;	/* 5e6 */
    val *= framesize;	/* 5e10 */
    val *= 8;		/* 5e11 */
    val /= bits_per_msec; /* assuming 10Gb/s, yields 5e4 */

    return val;
}

static u64
etfs_calc_tx_interval_usec(u32 framesize, u32 bits_per_msec)
{
    u64 val;

    /*
     * testing sometimes specifies very low rates: ensure we don't
     * try to divide by zero below.
     */
    if (!bits_per_msec)
	bits_per_msec= 1;

    /*
     * arrange calculation order to minimize chance of overflow
     * or loss of precision
     */
    val = framesize * 8 * 1000;
    val /= bits_per_msec;

    return val;
}

int
etfs_encap_new(etfs3_encap_new_arg_t *arg, macsec_sa_t *sa, int *error2)
{
    vlib_main_t			*vm = vlib_get_main();
    vnet_main_t			*vnm = vnet_get_main();
    bool			set_stea = false;
    u16				index;
    int				i;
    u32				new_sa_index;
    u32				next_index;
    vlib_node_t			*node_encap_rx = NULL;
    ethernet_max_header_t	ethernet_header = {0};
    int				vlans = 0;

    ETFS_DEBUG(ENCAP_FLOW, 1,
	"%s: entry (rxport=%u, txport=%u, CLIB_DEBUG=%s)\n",
	__func__, arg->rxport, arg->txport,
#if (CLIB_DEBUG > 0)
	"DEFINED"
#else
	"NOT defined"
#endif
	);


    node_encap_rx = vlib_get_node_by_name(vm, (u8*)"etfs-encap-rx");
    if (!node_encap_rx) {
	return VNET_API_ERROR_NO_SUCH_NODE;
    }

    if (sa && !macsec_enabled()) {
	/* macsec not available */
	return VNET_API_ERROR_FEATURE_DISABLED;
    }

    /*
     * dpdk-macsec-encrypt might not exist: plugin dependent
     */
    /* idempotent */
    next_index = vlib_node_add_named_next(vm, etfs_output_node.index,
	(sa? "dpdk-macsec-encrypt": "interface-output"));
    if (next_index == ~0)
	return VNET_API_ERROR_NO_SUCH_NODE2;

    clib_spinlock_lock(&etfs3_main.counter_lock);
    if (etfs_alloc_flow_index(ENCAP, &index)) {
	clib_spinlock_unlock(&etfs3_main.counter_lock);
	etfs3_log(VLIB_LOG_LEVEL_WARNING, "Exceeded max number encap flows");
	return VNET_API_ERROR_TABLE_TOO_BIG;
    }

    etfs_clear_flow_counters(ENCAP, index);

    clib_spinlock_unlock(&etfs3_main.counter_lock);


    /*
     * Validate thread for encap tx output. Caller can specify via
     * arg->worker_thread_index. A 0 value means to choose automatically.
     */
    u32 num_threads = vlib_num_workers() + 1;

    /* validate output thread configuration value */
    if (arg->worker_thread_index > (num_threads - 1)) {
	ETFS_DEBUG(ENCAP_FLOW, 1,
	    "%s: worker thread index %u larger than available threads %u\n",
	    __func__, arg->worker_thread_index, (num_threads - 1));
	return VNET_API_ERROR_INVALID_WORKER;
    }

    /*
     * Alloc encap flow struct
     */
    state_encap_flow_v2_t	*newflow;

    newflow = clib_mem_alloc_aligned(sizeof(state_encap_flow_v2_t), sizeof(u64));
    ASSERT((uintptr_t)newflow % sizeof(u64) == 0);
    memset(newflow, 0, sizeof(state_encap_flow_v2_t));

    newflow->config.next_index = next_index;

#if ETFS_DISABLE_ALL_PAD
    newflow->config.encap_no_pad_only = true;
#endif

    newflow->config.all_pad_trace = arg->all_pad_trace;

    /*
     * ethernet addrs and ethtype, part 1
     */
    u8	*p = ethernet_header.ethernet.src_address;

    for (i = 0; i < 6; ++i)
	p[i] = arg->stea[i];

    if (p[0] | p[1] | p[2] | p[3] | p[4] | p[5])
	set_stea = true;

    p = ethernet_header.ethernet.dst_address;

    for (i = 0; i < 6; ++i)
	p[i] = arg->dtea[i];

    ethernet_header.ethernet.type = clib_host_to_net_u16(ETFS_ETHERTYPE_TX);

    newflow->config.index = index;

    newflow->config.framesize = arg->framesize;
    newflow->config.max_aggr_time_usec = arg->max_aggr_time_usec;
    newflow->config.tx_rate_bits_msec = arg->tx_rate_bits_msec;
    newflow->config.min_fragment = 4; /* arbitrarily chosen */

    /*
     * Compute transmit interval based on output frame size and
     * target data rate
     */
    newflow->config.tx_interval_usec =
	etfs_calc_tx_interval_usec(arg->framesize, arg->tx_rate_bits_msec);
    newflow->config.tx_interval_cputicks =
	etfs_calc_tx_interval_cputicks(arg->framesize, arg->tx_rate_bits_msec);

    newflow->config.output_byte_counter_interval_cputicks = (u64)
	((vlib_get_main())->clib_time.clocks_per_second) *
	(ETFS_OUTPUT_BYTE_CTR_INTERVAL_SECS);

    /*
     * Max Aggregation Time has a lower bound of TX interval for modes 2/3.
     */
    newflow->config.max_aggr_time_bounded_usec =
	(arg->max_aggr_time_usec > newflow->config.tx_interval_usec)?
	arg->max_aggr_time_usec: newflow->config.tx_interval_usec;

    /*
     * Calculate queue depth in bytes based on max aggregation time
     * and data rate.
     *
     * Be careful of multiply/divide order to avoid losing precision.
     */
    u64 max_queue_depth_bytes_64 =
	newflow->config.max_aggr_time_bounded_usec *
	newflow->config.tx_rate_bits_msec / (8 * 1000);

    /*
     * Very slow rates can end up with a tiny queue that is the same size
     * as a tunnel frame, which can cause the encap code to think there is
     * never enough room for even a single packet. Rather than go through
     * painstaking analysis to find where < should be <= for this
     * unlikely case, just punt and round up a bit.
     */
    if (max_queue_depth_bytes_64 <= (newflow->config.framesize + 20))
	max_queue_depth_bytes_64 += 20;	/* arbitrary small number */

    /*
     * make sure it fits in 32 bits
     *
     * This is an internal error but let's just fail creating the
     * tunnel instead of crashing the system.
     */
    if ((max_queue_depth_bytes_64 & 0xffffffff) != max_queue_depth_bytes_64) {
	_ef_cleanup(newflow);
	return VNET_API_ERROR_LIMIT_EXCEEDED;
    }
    newflow->config.max_queue_depth_bytes =
	max_queue_depth_bytes_64 & 0xffffffff;

    /* copy to pacer queue limit field */
    newflow->encap.pacer_queue_depth.max_size =
	newflow->config.max_queue_depth_bytes;

    /*
     * Calculate max number of packets in queue based on
     * max-queue-depth-in-bytes and frame size
     */
    u32 max_queue_depth_packets = newflow->config.max_queue_depth_bytes /
	newflow->config.framesize;
    max_queue_depth_packets += 1;	/* round up */

    /* margin - experiment */
    max_queue_depth_packets *= 1.1;

    ETFS_DEBUG(ENCAP_FLOW, 1,
	"%s: framesize %u, tx-rate (b/ms) %u, maxagg (us) %lu, "
	"qdepth (B) %u, qdepth (pkts) %u, interval-ticks %lu\n",
	__func__,
	newflow->config.framesize,
	newflow->config.tx_rate_bits_msec,
	newflow->config.max_aggr_time_bounded_usec,
	newflow->config.max_queue_depth_bytes,
	max_queue_depth_packets,
	newflow->config.tx_interval_cputicks);

    /*
     * Calculate number of buffers for encap tunnel packets
     * a. Full queue (max_queue_depth_packets)
     * b. packets sent to next node but still in transit (not freed yet)
     *    Assume 2 * VLIB_FRAME_SIZE per similar iptfs calculation
     *
     * Encap path does not use indirect/chained buffers, so we don't
     * need to adjust buffer pool sizes for that case.
     */
    u32	zpool_target_size;

    zpool_target_size = (2 * VLIB_FRAME_SIZE) + max_queue_depth_packets;

    /* limit to some max */
    zpool_target_size = clib_min (zpool_target_size, ETFS_ZPOOL_MAX_ALLOC);

    /* cargo-cult copied from iptfs: why is this important? */
#define UROUND(x, to) ((((x) + (to)-1) / (to)) * (to))
    zpool_target_size = UROUND (zpool_target_size, VLIB_FRAME_SIZE);

    newflow->config.if_index_rx = arg->rxport;
    newflow->config.if_index_tx = arg->txport;

    newflow->config.tx_port_is_dpdk = is_dpdk_interface(arg->txport);

    /* TBD register for callbacks upon mtu change so we can adapt */
    /* VNET_MTU_L3 means "Default payload MTU (without L2 headers)" */
    newflow->config.tx_mtu =
	vnet_sw_interface_get_mtu(vnm, arg->txport, VNET_MTU_L3);

    if (newflow->config.tx_mtu < newflow->config.framesize) {
	_ef_cleanup(newflow);
	/* Use this code ONLY for framesize too big */
	return VNET_API_ERROR_INVALID_VALUE;
    }

    vnet_sw_interface_t	*sw = vnet_get_sup_sw_interface(vnm, arg->rxport);
    if (sw == NULL) {
	_ef_cleanup(newflow);
	return VNET_API_ERROR_INVALID_INTERFACE;
    }

#if ETFS_PORTS_PHYSICAL_ONLY
    ASSERT (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
#endif
    newflow->config.if_hw_index_rx = sw->hw_if_index;
    newflow->config.if_sw_index_rx = sw->sw_if_index;

    sw = vnet_get_sw_interface(vnm, arg->txport);
    if (sw == NULL) {
	_ef_cleanup(newflow);
	return VNET_API_ERROR_INVALID_INTERFACE;
    }

    /*
     * ethernet part 2
     */

    /*
     * We have to do our own 802.1q tagging for now
     */
    if (sw->type == VNET_SW_INTERFACE_TYPE_SUB) {
	if (sw->sub.eth.flags.one_tag) {
	    /* host byte order */
	    ethernet_header.vlan[0].priority_cfi_and_id = 
		sw->sub.eth.outer_vlan_id;
	    vlans = 1;
	} else if (sw->sub.eth.flags.two_tags) {
	    /* two tags not supported */
	    _ef_cleanup(newflow);
	    return VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;
	}
    }

    if (!set_stea) {
	struct vnet_hw_interface_t *hwif;

	hwif = vnet_get_hw_interface(etfs3_main.vnet_main, sw->hw_if_index);
	if (vec_len(hwif->hw_address) != sizeof(arg->stea)) {
		_ef_cleanup(newflow);
		return VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
	}
	memcpy(ethernet_header.ethernet.src_address, hwif->hw_address,
		sizeof(ethernet_header.ethernet.src_address));
    }

    /*
     * construct ethernet header
     */
    memcpy(newflow->config.ether_header + 0,
	ethernet_header.ethernet.dst_address,
	6);
    memcpy(newflow->config.ether_header + 6,
	ethernet_header.ethernet.src_address,
	6);
    if (vlans) {
	u16 tmp;

	tmp = clib_host_to_net_u16(ETHERNET_TYPE_VLAN);
	memcpy(newflow->config.ether_header + 12,
	    (u8 *)&tmp, 2);
	tmp = clib_host_to_net_u16(ethernet_header.vlan[0].priority_cfi_and_id);
	memcpy(newflow->config.ether_header + 14,
	    (u8 *)&tmp, 2);
	memcpy(newflow->config.ether_header + 16,
	    (u8 *)&ethernet_header.ethernet.type, 2);
	newflow->config.ether_header_len = 18;
    } else {
	memcpy(newflow->config.ether_header + 12,
	    (u8 *)&ethernet_header.ethernet.type, 2);
	newflow->config.ether_header_len = 14;
    }


    /*
     * index on receive sw interface index
     */
    BVT (clib_bihash_kv)	search;
    BVT (clib_bihash_kv)	result;

    clib_spinlock_lock(&etfs3_main.encap_flow_table_lock);

    search.key = arg->rxport;
    if (!BV(clib_bihash_search)(&etfs3_main.encap_flow_table,
	&search, &result)) {

	/* already handling received packets on this interface: fail */
	clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);
	_ef_cleanup(newflow);
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

    search.value = (uintptr_t) newflow;
    /* check return value */
    if (BV(clib_bihash_add_del)(&etfs3_main.encap_flow_table, &search, 1 /*add*/)) {
	clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);
	_ef_cleanup(newflow);
	return VNET_API_ERROR_TABLE_TOO_BIG;
    }
    newflow->allocated.parent_flow_table_entry = true;

    ETFS_DEBUG(ENCAP_FLOW, 1, "%s: newflow key: %lu\n", __func__, search.key);

    if (sa && ((i = macsec_sa_add(index | MACSEC_SA_ID_ETFS_ENCAP,
        sa, &new_sa_index)))) {

        /* failed to add SA */
	clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);
	_ef_cleanup(newflow);

	ETFS_DEBUG(ENCAP_FLOW, 1, "%s: Can't add macsec SA\n", __func__);

	/* return secondary error code if caller wants it */
	if (error2)
	    *error2 = i;

	return VNET_API_ERROR_SYSCALL_ERROR_1; /* means: can't create SA */
    }

    if (sa) {
	newflow->allocated.macsec_sa = true;
        newflow->config.macsec_enabled = 1;
        newflow->config.ipsec_sa_index = new_sa_index;
	ETFS_DEBUG(ENCAP_FLOW, 1, "%s: macsec: ipsec_sa_index: %u\n",
	    __func__, new_sa_index);
    }

    /*
     * queue from encap to pacer
     */
    iptfs_bufq_init(&newflow->encap.pacer_queue, max_queue_depth_packets);
    newflow->allocated.encap_to_pacer_q = true;
    newflow->encap.pacer_queue_depth.max_size = newflow->config.max_queue_depth_bytes;

    /* mark inprogress buffer as unallocated */
    newflow->encap.bi_inprogress = ~0u;

#if ETFS_ENABLE_ELOG
    /*
     * various elog things
     */
    newflow->encap.pacer_track.name = (char *)format(0, "ef-enc-pacer %u%c",
	newflow->config.index, 0);
    newflow->allocated.encap_pacer_track_name = true;
    elog_track_register(&vlib_global_main.elog_main,
	&newflow->encap.pacer_track);
    newflow->allocated.encap_pacer_track_elog = true;

    newflow->encap.zpool_track.name = (char *)format(0, "ef-enc-zpool %u%c",
	newflow->config.index, 0);
    newflow->allocated.encap_zpool_track_name = true;
    elog_track_register(&vlib_global_main.elog_main,
	&newflow->encap.zpool_track);
    newflow->allocated.encap_zpool_track_elog = true;

    newflow->encap.error_track.name = (char *)format(0, "ef-enc-error %u%c",
	newflow->config.index, 0);
    newflow->allocated.encap_error_track_name = true;
    elog_track_register(&vlib_global_main.elog_main,
	&newflow->encap.error_track);
    newflow->allocated.encap_error_track_elog = true;

    newflow->output.output_track.name = (char *)format(0, "ef-out-output %u%c",
	newflow->config.index, 0);
    newflow->allocated.output_output_track_name = true;
    elog_track_register(&vlib_global_main.elog_main,
	&newflow->output.output_track);
    newflow->allocated.output_output_track_elog = true;

    newflow->output.zpool_track.name = (char *)format(0, "ef-out-zpool %u%c",
	newflow->config.index, 0);
    newflow->allocated.output_zpool_track_name = true;
    elog_track_register(&vlib_global_main.elog_main,
	&newflow->output.zpool_track);
    newflow->allocated.output_zpool_track_elog = true;

    newflow->output.error_track.name = (char *)format(0, "ef-out-error %u%c",
	newflow->config.index, 0);
    newflow->allocated.output_error_track_name = true;
    elog_track_register(&vlib_global_main.elog_main,
	&newflow->output.error_track);
    newflow->allocated.error_track_elog = true;
#endif /* ETFS_ENABLE_ELOG */

    /*
     * Initialize etfs-encap zpool
     */
    newflow->encap.zpool = etfs_zpool_alloc(vm, zpool_target_size, 
	newflow->config.framesize, newflow->config.ether_header,
	newflow->config.ether_header_len,
	newflow->config.if_index_tx,
	false,
	&newflow->encap.zpool_track,
	&newflow->encap.error_track);

    newflow->allocated.encap_zpool = true;

    /*
     * Initialize etfs-output zpool
     */
    newflow->output.zpool = etfs_zpool_alloc(vm, ETFS_OUTPUT_ZPOOL_SIZE, 
	newflow->config.framesize, newflow->config.ether_header,
	newflow->config.ether_header_len,
	newflow->config.if_index_tx,
	true,
	&newflow->output.zpool_track,
	&newflow->output.error_track);
    newflow->allocated.output_zpool = true;

    /*
     * preload transmit metering timestamp so that the first iteration of
     * the output loop doesn't send a giant bolus of packets.
     */
    newflow->output.next_desired_tx_cputicks = clib_cpu_time_now();

    /*
     * To measure output data rate
     */
    etfs_output_byte_counter_q_init(newflow);
    newflow->allocated.output_byte_counter_q = true;

#if ETFS_RX_INTERFACE_REDIRECT
    /*
     * Tell receive code to send us all packets on the target receive interface
     */
    int rc = vnet_hw_interface_rx_redirect_to_node(
	vnm, newflow->config.if_hw_index_rx, node_encap_rx->index);
#else
    /*
     * Using xcrw tunnel allows for better packet tracing.
     */
    int rc = vnet_configure_l2_xcrw(vm, vnm,
#if 1	/* probably correct for vlan interfaces. seems ok for normal i/f */
	newflow->config.if_index_rx,
#else
	newflow->config.if_sw_index_rx,
#endif
	~0 /* tx_fib_index */, NULL /* no rewriting */,
	node_encap_rx->index, 1 /* add */);
#endif
    if (rc) {
	printf("%s: Can't redirect received packets on rxport %u\n",
	    __func__, arg->rxport);
	ETFS_DEBUG(ENCAP_FLOW, 1,
	    "Can't redirect received packets on rxport %u\n",
	    arg->rxport);
	clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);
	_ef_cleanup(newflow);
	return rc;
    }

    newflow->config.send_direct_bufs_only =
	newflow->config.macsec_enabled || !newflow->config.tx_port_is_dpdk;

    clib_spinlock_unlock(&etfs3_main.encap_flow_table_lock);

    /*
     * places all pollers in encap path onto threads
     */
    u32 tid = etfs_thread_encap_place(newflow,
	(arg->worker_thread_index? &arg->worker_thread_index: NULL));
    ETFS_DEBUG_F(ENCAP_FLOW, 3, "output thread index %u\n", tid);

    /* Set promiscuous mode on the l2 interface */
    ethernet_set_flags (etfs3_main.vnet_main, newflow->config.if_hw_index_rx,
                        ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

    etfs_set_flow_index(ENCAP, index, newflow);

    return 0;
}

int
etfs_decap_new(etfs3_decap_new_arg_t *arg, macsec_sa_t *sa, int *error2)
{
    ETFS_DEBUG(DECAP_FLOW, 1, "entry (rxport=%u, txport=%u)\n",
	arg->rxport,
	arg->txport);

    vnet_main_t			*vnm = vnet_get_main();
    u16				 index;
    int				 i;
    u32		 		 new_sa_index;

    if (sa && !macsec_enabled()) {
	/* macsec not available */
	return VNET_API_ERROR_FEATURE_DISABLED;
    }

    clib_spinlock_lock(&etfs3_main.counter_lock);
    if (etfs_alloc_flow_index(DECAP, &index)) {
	clib_spinlock_unlock(&etfs3_main.counter_lock);
	etfs3_log(VLIB_LOG_LEVEL_WARNING, "Exceeded max number decap flows");
	return VNET_API_ERROR_TABLE_TOO_BIG;
    }

    etfs_clear_flow_counters(DECAP, index);
    clib_spinlock_unlock(&etfs3_main.counter_lock);


    /*
     * Alloc encap flow struct
     */
    state_decap_flow_v2_t	*newflow;

    newflow = clib_mem_alloc_aligned(sizeof(state_decap_flow_v2_t), sizeof(u64));
    memset(newflow, 0, sizeof(state_decap_flow_v2_t));

    newflow->config.index = index;
    newflow->config.if_index_rx = arg->rxport;
    newflow->config.if_index_tx = arg->txport;
    /* TBD make window configurable via api */
    newflow->config.maxwin = ETFS_DEFAULT_RX_FRAG_WINDOW;

    newflow->config.tx_port_is_dpdk = is_dpdk_interface(arg->txport);

    vnet_sw_interface_t	*sw = vnet_get_sup_sw_interface(vnm, arg->rxport);
#if ETFS_PORTS_PHYSICAL_ONLY
    ASSERT (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
#endif
    newflow->config.if_hw_index_rx = sw->hw_if_index;

    /* TBD register for callbacks upon mtu change so we can adapt */
    /* VNET_MTU_L3 means "Default payload MTU (without L2 headers)" */
    newflow->config.tx_mtu = vnet_sw_interface_get_mtu(vnm, arg->txport, VNET_MTU_L3);

    /*
     * index on receive sw interface index
     */
    BVT (clib_bihash_kv)	search;
    BVT (clib_bihash_kv)	result;
    BVT(clib_bihash)		*pDecapFlowTable;

    pDecapFlowTable = sa?
	&etfs3_main.decap_flow_table_macsec:
	&etfs3_main.decap_flow_table;

    search.key = arg->rxport;
    if (!BV(clib_bihash_search)(pDecapFlowTable, &search, &result)) {

	/* already handling received packets on this interface: fail */
	_df_cleanup(pDecapFlowTable, newflow);
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

    search.value = (uintptr_t) newflow;
    /* TBD is this change to the bihash thread-safe? */
    if (BV(clib_bihash_add_del)(pDecapFlowTable, &search, 1 /*add*/)) {
	_df_cleanup(pDecapFlowTable, newflow);
	return VNET_API_ERROR_TABLE_TOO_BIG;
    }
    newflow->allocated.parent_flow_table_entry = true;

    ETFS_DEBUG(DECAP_FLOW, 1, "%s: newflow key: %lu\n", __func__, search.key);

    if (sa && ((i = macsec_sa_add(index | MACSEC_SA_ID_ETFS_DECAP,
        sa, &new_sa_index)))) {

	/* failed to add SA */
	ETFS_DEBUG(DECAP_FLOW, 1, "%s: Can't add macsec SA\n", __func__);
	_df_cleanup(pDecapFlowTable, newflow);

	/* return secondary error code if caller wants it */
	if (error2)
	    *error2 = i;

	return VNET_API_ERROR_SYSCALL_ERROR_1; /* means: can't create SA */
    }

    if (sa) {
        newflow->config.ipsec_sa_index = new_sa_index;
	newflow->config.macsec_enabled = 1;
	ETFS_DEBUG(DECAP_FLOW, 1, "macsec sa index: %u\n", new_sa_index);
    }

    etfs_thread_decap_place(newflow);

    etfs_set_flow_index(DECAP, index, newflow);

    return 0;
}


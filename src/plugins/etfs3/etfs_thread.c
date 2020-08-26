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
#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vnet/interface.h>
#include <vnet/devices/devices.h>

#include <plugins/etfs3/etfs3.h>
#include <plugins/etfs3/etfs_thread.h>

u32
etfs_encap_node_index(etfs_encap_polling_node_type_t nodetype)
{
    switch(nodetype) {
	case ETFS_ENCAP_POLLER_PACER:
	    return etfs_encap_pacer_node.index;
	case ETFS_ENCAP_POLLER_ZPOOL:
	    return etfs_zpool_poll_node.index;
	case ETFS_ENCAP_POLLER_OUTPUT:
	    return etfs_output_node.index;
	default:
	    ASSERT(0);
    }
    return ~0u;
}

u32
etfs_decap_node_index(etfs_decap_polling_node_type_t nodetype)
{
    switch(nodetype) {
	case ETFS_DECAP_POLLER_PROCESSOR:
	    return etfs_decap_processor_node.index;
	default:
	    ASSERT(0);
    }
    return ~0u;
}

const char *
etfs_encap_node_type_str(etfs_encap_polling_node_type_t nodetype)
{
    switch(nodetype) {
	case ETFS_ENCAP_POLLER_PACER:
	    return "PACER";
	case ETFS_ENCAP_POLLER_ZPOOL:
	    return "ZPOOL";
	case ETFS_ENCAP_POLLER_OUTPUT:
	    return "OUTPUT";
	default:
	    ASSERT(0);
    }
    return "?";
}

const char *
etfs_decap_node_type_str(etfs_decap_polling_node_type_t nodetype)
{
    switch(nodetype) {
	case ETFS_DECAP_POLLER_PROCESSOR:
	    return "DECAP_PROCESSOR";
	default:
	    ASSERT(0);
    }
    return "?";
}

/*
 * enable/disable the specified flow in the polling node of type <nodetype> 
 * on the specified thread. Transitions from 0->1 or 1->0 enabled flows
 * on a {node,thread} enable or disable the node on the thread, respectively.
 * Based on similar iptfs function.
 */
static void
etfs_thread_encap_flow_set(
    state_encap_flow_v2_t		*ef,
    etfs_encap_polling_node_type_t	nodetype,
    u32					thread_index,
    bool				enable)
{
    vlib_main_t				*vm = vlib_mains[thread_index];
    u32					node_index = etfs_encap_node_index(nodetype);
    etfs_thread_main_t			*tm;

    vec_validate(etfs3_main.workers_main, thread_index);
    tm = vec_elt_at_index(etfs3_main.workers_main, thread_index);

    ETFS_DEBUG_F(THREAD_FLOW_SET, 1, "nodetype %s, thread_index %u, %s\n",
	etfs_encap_node_type_str(nodetype),
	thread_index,
	(enable? "enable": "disable"));

    uint fi = vec_search(tm->flows[nodetype], ef);
    if (enable) {
	ASSERT(fi == ~0u);
	vec_add1(tm->flows[nodetype], ef);
	if (vec_len(tm->flows[nodetype]) == 1) {
	    vlib_node_set_state(vm, node_index, VLIB_NODE_STATE_POLLING);
	}
	ef->thread.thread_id[nodetype] = thread_index;
    } else {
	ASSERT(fi != ~0u);
	vec_del1(tm->flows[nodetype], fi);
	if (vec_len(tm->flows[nodetype]) == 0) {
	    vlib_node_set_state(vm, node_index, VLIB_NODE_STATE_DISABLED);
	}
    }
    ef->thread.node_running[nodetype] = enable;
}

static void
etfs_thread_decap_flow_set(
    state_decap_flow_v2_t		*df,
    etfs_decap_polling_node_type_t	nodetype,
    u32					thread_index,
    bool				enable)
{
    vlib_main_t				*vm = vlib_mains[thread_index];
    u32					node_index = etfs_decap_node_index(nodetype);
    etfs_thread_main_t			*tm;

    vec_validate(etfs3_main.workers_main, thread_index);
    tm = vec_elt_at_index(etfs3_main.workers_main, thread_index);

    ETFS_DEBUG_F(THREAD_FLOW_SET, 1, "nodetype %s, thread_index %u, %s\n",
	etfs_decap_node_type_str(nodetype),
	thread_index,
	(enable? "enable": "disable"));

    uint fi = vec_search(tm->flows_decap[nodetype], df);
    if (enable) {
	ASSERT(fi == ~0u);
	vec_add1(tm->flows_decap[nodetype], df);
	if (vec_len(tm->flows_decap[nodetype]) == 1) {
	    vlib_node_set_state(vm, node_index, VLIB_NODE_STATE_POLLING);
	}
	df->thread.thread_id[nodetype] = thread_index;
    } else {
	ASSERT(fi != ~0u);
	vec_del1(tm->flows_decap[nodetype], fi);
	if (vec_len(tm->flows_decap[nodetype]) == 0) {
	    vlib_node_set_state(vm, node_index, VLIB_NODE_STATE_DISABLED);
	}
    }
    df->thread.node_running[nodetype] = enable;
}

#if 0
static u32
count_output_pollers(u32 thread_index)
{
    etfs_thread_main_t		*tm;

    vec_validate(etfs3_main.workers_main, thread_index);
    tm = vec_elt_at_index(etfs3_main.workers_main, thread_index);

    return vec_len(tm->flows[ETFS_ENCAP_POLLER_OUTPUT]);
}
#endif

/*
 * This walker callback function identifies all threads that poll an
 * administratively "up" interface.
 */
static walk_rc_t
_interface_walker_rx_thread_finder(
    vnet_main_t		*vnm,
    vnet_sw_interface_t	*si,
    void		*ctx)
{
    u32	**eligible_threads = (u32 **)ctx;

    if (vec_len(*eligible_threads) == 0)
	return WALK_STOP;

    if (vnet_sw_interface_is_admin_up(vnm, si->sw_if_index)) {
	vnet_sw_interface_t *sw_sup =
	    vnet_get_sup_sw_interface(vnm, si->sw_if_index);
	if (sw_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE) {
	    /*
	     * Some interfaces (e.g., tunnel interfaces), which we
	     * don't care about, do not have an input poller thread.
	     * If this thread index vector is empty, the "get
	     * input thread" call below will fail in an assertion,
	     * so catch it beforehand.
	     */
	    vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm,
		sw_sup->hw_if_index);
	    if (!vec_len(hw->input_node_thread_index_by_queue))
		return WALK_CONTINUE;

	    /* assume queue 0 */
	    u32 rx_thread_index = vnet_get_device_input_thread_index(
		vnm, sw_sup->hw_if_index, 0);
	    u32 idx = vec_search(*eligible_threads, rx_thread_index);
	    if (~0u != idx) {
		vec_del1(*eligible_threads, idx);
	    }
	}
    }

    return WALK_CONTINUE;
}

static u32
etfs_thread_assign_output_thread(u32 num_threads)
{
    vnet_main_t		*vnm = vnet_get_main();
    static u32		next_thread_id;
    static u32		next_eligible_index;

    /*
     * output thread: see if there are any threads without encap
     * receive on them.
     */
    /* Are there any threads that are not polling an "up" interface? */
    u32	*eligible_threads = NULL;

    /* start with complete list of worker threads */
    for (u32 i = 1; i < num_threads; ++i) {
	vec_add1(eligible_threads, i);
    }

    /* remove threads that are already polling admin "up" interfaces */
    vnet_sw_interface_walk(vnm, _interface_walker_rx_thread_finder,
	&eligible_threads);

    u32	vl;
    u32	tid = ~0u;

    switch ((vl = vec_len(eligible_threads))) {
	case 0:
	    /*
	     * choose any worker - attempt round-robin
	     */
	    if (!next_thread_id)
		++next_thread_id;
	    tid = next_thread_id;
	    ++next_thread_id;
	    if (next_thread_id >= num_threads)
		next_thread_id = 0;
	    break;

	case 1:
	    /*
	     * Only one worker not polling an "up" interface - pick it
	     */
	    tid = vec_elt(eligible_threads, 0);
	    break;

	default:
	    /*
	     * choose any worker not polling an "up" interface - attempt
	     * round-robin
	     */
	    if (next_eligible_index >= vl)
		next_eligible_index = 0;
	    tid = vec_elt(eligible_threads, next_eligible_index);
	    ++next_eligible_index;
	    break;
    }

    return tid;
}

/*
 * Place encap path nodes for this encap flow on threads.
 *
 * There are three nodes: pacer, zpool filler, output.
 * The pacer and zpool nodes for this flow get put on the thread
 * that is handling the receive interface. The output poller
 * gets placed either on the specified thread (output_thread_index non-NULL)
 * or we pick a thread to put it on (output_thread_index is NULL).
 *
 * If non-null, the index value dereferenced by output_thread_index means:
 * 0 = main thread
 * 1 = worker thread 1
 * N = worker thread N
 *
 * If there are no worker threads (i.e., only the main thread), then
 * everything goes onto thread 0.
 */
u32
etfs_thread_encap_place(
    struct state_encap_flow_v2	*ef,
    u32				*output_thread_index)	/* NULL = auto */
{
#if 0
    static u32		next_thread_id;
    static u32		next_eligible_index;
#endif
    vnet_main_t		*vnm = vnet_get_main();
    u32			tid;

    /*
     * Thread 0 is the main thread; worker thread indices start at 1.
     *
     * Encap nodes:
     *	- pacer on same thread as plaintext receive interface
     *	- output on different worker thread than pacer/zpool filler
     *
     * FORMERLY:
     *	- zpool filler on same thread as pacer (inverse load relationship)
     * NOW:
     *  - zpool filler: try to assign to unused thread as it now also
     *    fills buffers for the encap node (receive interface thread)
     */

    u32 num_threads = vlib_num_workers() + 1;

    /*
     * We need to stash the rx thread index in any case. Assume
     * that there is no receive-side scaling (RSS) and therefore
     * that we should pick the thread that polls queue 0.
     */
    ef->encap.rx_thread_index =
	vnet_get_device_input_thread_index(vnm, ef->config.if_hw_index_rx, 0);

    /*
     * if no workers, everything goes on thread 0
     */
    if (num_threads == 1) {
	etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_PACER, 0, true);
	etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_ZPOOL, 0, true);
	etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_OUTPUT, 0, true);
	return 0;	/* output thread index */
    }

    /*
     * At least one worker: put the pacer and zpool filler on the
     * same thread that is polling the receive interface. Try to
     * place the output generator on another thread.
     */
    etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_PACER, ef->encap.rx_thread_index, true);
#if ETFS_ZPOOL_THREAD_SAME_AS_RX
    etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_ZPOOL, ef->encap.rx_thread_index, true);
#endif

    /*
     * explicit placement of output poller
     */
    if (output_thread_index) {
	etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_OUTPUT, *output_thread_index,
	    true);
	return *output_thread_index;
    }

    /*****************************************************************
     *		Auto placement of output poller
     *****************************************************************/

    tid = etfs_thread_assign_output_thread(num_threads);

    etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_OUTPUT, tid, true);

#if ! ETFS_ZPOOL_THREAD_SAME_AS_RX
    tid = etfs_thread_assign_output_thread(num_threads);
    etfs_thread_encap_flow_set(ef, ETFS_ENCAP_POLLER_ZPOOL, tid, true);
#endif

    return tid;
}

/*
 * There is only one placeable node for the decap path, viz., the
 * decoupler, which runs on the same thread as the decap receive interface.
 */
void
etfs_thread_decap_place(
    struct state_decap_flow_v2	*df)
{
    vnet_main_t		*vnm = vnet_get_main();
    u32			tid;

    /*
     * Thread 0 is the main thread; worker thread indices start at 1.
     *
     * Decap nodes:
     *	- decoupler on same thread as tunnel receive interface
     */

    u32 num_threads = vlib_num_workers() + 1;

    /*
     * We need to stash the rx thread index in any case. Assume
     * that there is no receive-side scaling (RSS) and therefore
     * that we should pick the thread that polls queue 0.
     */
    df->decoupler.rx_thread_index =
	vnet_get_device_input_thread_index(vnm, df->config.if_hw_index_rx, 0);

    /*
     * if no workers, everything goes on thread 0
     */
    if (num_threads == 1) {
	etfs_thread_decap_flow_set(df, ETFS_DECAP_POLLER_PROCESSOR, 0, true);
    }

#if ETFS_DECAP_PROCESSOR_THREAD_SAME_AS_RX
    /*
     * At least one worker: put the decoupler on the
     * same thread that is polling the receive interface.
     */
    tid = df->decoupler.rx_thread_index;
#else
    tid = etfs_thread_assign_output_thread(num_threads);
#endif

    etfs_thread_decap_flow_set(df, ETFS_DECAP_POLLER_PROCESSOR, tid, true);
}

void
etfs_thread_encap_unplace(struct state_encap_flow_v2 *ef)
{
#define _(E) {							 	  \
    if (ef->thread.node_running[E])					  \
	etfs_thread_encap_flow_set(ef, E, ef->thread.thread_id[E], false);\
  }

    foreach_etfs_encap_polling_node_type

#undef _
}

void
etfs_thread_decap_unplace(struct state_decap_flow_v2 *df)
{
#define _(E) {							 	  \
    if (df->thread.node_running[E])					  \
	etfs_thread_decap_flow_set(df, E, df->thread.thread_id[E], false);\
  }

    foreach_etfs_decap_polling_node_type

#undef _
}


/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

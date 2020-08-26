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

#ifndef included_etfs3_h
#define included_etfs3_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>
#include <stdatomic.h>
#include <vnet/ethernet/packet.h>
#include <vnet/macsec/macsec_sa.h>

#undef IPTFS_BUFQ_DEBUG
#include <plugins/iptfs/iptfs_bufq.h>

#include <plugins/iptfs/iptfs_sring.h>

/*
 * Enable/disable options
 */
#define ETFS_TX_MULTISEG_INDIRECT	0
#define ETFS_ENABLE_BUFFER_NOTES	0
#define ETFS_DISABLE_ALL_PAD		0
#define ETFS_VERIFY_TRAILING_PAD	0	/* Slooooow. For testing only */
#define ETFS_ENABLE_ELOG		0	/* dbg, not fully implemented */
#define ETFS_DEBUG_FFC_IN_EXPLICIT_PAD	0
#define ETFS_ZPOOL_THREAD_SAME_AS_RX	0
#define ETFS_DECAP_PROCESSOR_THREAD_SAME_AS_RX 0
#define ETFS_PAD_SIZE_EXPERIMENT_1	0

/*
 * Allow options defined above to influence behavior of our own header files
 */
#include <plugins/etfs3/etfs_debug.h>
#include <plugins/etfs3/etfs_thread.h>
#include <plugins/etfs3/etfs_buffer.h>
#include <plugins/etfs3/etfs_zpool.h>
#include <plugins/etfs3/etfs_counter.h>

#define ETFS_MTDU_FRAME_SIZE_DEFAULT 1400
#define ETFS_TX_RATE_BITSPERMSEC_DEFAULT 200
#define ETFS_MAX_AGGR_TIME_USEC_DEFAULT 10000

#define ETFS_ETHERTYPE_TX 0x8552

#define ETFS_MAX_ETHERNET_HEADER_SIZE	(	\
	sizeof(ethernet_header_t) + (2 * sizeof(ethernet_vlan_header_t)))

/*
 * top 2 bits of first byte of MPPDU Components: identify component type
 */
#define ETFS_MPPCI_ID_MASK8		0xc0
#define ETFS_MPPCI_ID_MASK16		0xc000
#define ETFS_MPPCI_GET_ID(BYTE) (BYTE & ETFS_MPPCI_ID_MASK8)
#define ETFS_MPPCI_ID_FRAGMENT		0x80
#define ETFS_MPPCI_ID_EXPLICIT_PAD	0x40
#define ETFS_MPPCI_ID_FRAME		0x00

/*
 * Fragment flags: part of 3rd octet
 */
#define ETFS_MPPCI_FRAG_INITIAL		0x40
#define ETFS_MPPCI_FRAG_FINAL		0x20
#define ETFS_MPPCI_FRAG_EXPRESS		0x10

/*
 * Transmission Interval as defined in ETFS spec
 */
#define ETFS_CALC_TX_INTERVAL_USEC(framesize, bits_per_msec) \
    ((framesize) * 8 * 1000 / (bits_per_msec))

#define ETFS_CALC_TX_INTERVAL_CPUTICKS(framesize, bits_per_msec)	   \
    ( ((framesize) * 8 * (vlib_get_main())->clib_time.clocks_per_second) / \
	(1000 * (bits_per_msec))  )

/*
 * How big to make the data area of the small buffers used for small
 * chunks of interleaved "offset/size" tunnel fields, and also for
 * the indirect buffers (which don't use their own data area at all)
 */
#define ETFS3_SMALL_BUFFER_DATA_SIZE	32

#define ETFS3_PAD_BYTES_MAX		9500
/* overhead must be big enough for aligned struct rte_mbuf_ext_shared_info */
#define ETFS3_PAD_OVH			200
#define ETFS3_PAD_BUFFER_SIZE		(ETFS3_PAD_BYTES_MAX + ETFS3_PAD_OVH)


#define ENCAP_FLOW_TBL_NUM_BUCKETS	32
#define ENCAP_FLOW_TBL_MEMORY_SIZE	(20*1024)

/*
 * Maximum number of segments in transmitted packets. Currently
 * known to be a limitation in the Marvell pp2 driver (PP2_PPIO_DESC_NUM_FRAGS)
 */
#define ETFS_TX_MAX_SEGS		16

/* size of pacer->transmit queue */
#define ETFS_TXQ_LOG2 15

#define ETFS_PACER_MAX_BURST 16

/* size of decap decoupler/processor queue */
#define ETFS_DDQ_LOG2 13

#define ETFS_DECAP_MAX_PROCESS_PER_ITER	32

/* 9K pkt in 1K tunnel pkt = 9+/- fragments. */
#define ETFS_DEFAULT_RX_FRAG_WINDOW	32

/* maximum number of flows of each type */
#define ETFS_MAX_FLOWS	255

/*
 * Zpool sizes
 *
 * There are two zpools used by the encapsulator:
 *
 *	- all-pad consumed by etfs-output
 *	- pre-zeroed consumed by etfs-encap for payload-bearing tunnel pkts
 *
 * The payload-bearing packets are pre-zeroed by the zpool worker so that 
 * the busy etfs-encap/etfs-pacer nodes don't have to add trailing pad
 * (via memcpy()) themselves.
 *
 * The all-pad packets are also, of course, pre-zeroed by the zpool worker.
 */

/* encap pool size is calculated dynamically when an encap flow is added */

/* output pool is for all-pad packets */
#define ETFS_OUTPUT_ZPOOL_SIZE (VLIB_FRAME_SIZE * 8)

/*
 * from iptfs:
 * IPTFS_ZPOOL_MAX_ALLOC  is a sanity value to make sure the user doesn't
 * specify a max latency so large that we pre-allocate too many zero buffers
 */
#define ETFS_ZPOOL_MAX_ALLOC (VLIB_FRAME_SIZE * 1024)


/*
 * ELOG
 */
#define ETFS_ELOGP(e, t) \
    elog_data_inline (&vlib_global_main.elog_main, (e), (t))

#define ETFS_ELOG(e, t) \
    ELOG_TRACK_DATA_INLINE (&vlib_global_main.elog_main, (e), (t))

#define ETFS_ELOG_DEFAULT_TRACK(e) \
    ELOG_TRACK_DATA_INLINE (&vlib_global_main.elog_main, (e), \
	vlib_global_main.elog_main.default_track)

#define ETFS_ELOG_THREAD(e, thread_index) \
    ETFS_ELOG ((e), vlib_worker_threads[(thread_index)].elog_track)

#define ETFS_ELOG_CURRENT_THREAD(e) \
    ETFS_ELOG_THREAD ((e), vlib_get_thread_index ())



/*
 * One of these per vpp thread. Each one has a vector of encap flows
 * corresponding to the encap TX flows that the thread should generate.
 */
struct encap_tx_thread {
    u32				thread_index;
    struct state_encap_flow_v2	**flows;
    struct state_decap_flow_v2	**flows_decap;
    clib_spinlock_t		flow_lock;
};

typedef enum {
    ENCAP,
    DECAP,
    N_ETFS_FLOW_TYPES
} etfs_flow_type_t;

/*
 * top-level structure holding state for this node.
 */
typedef struct etfs3_main {

    BVT(clib_bihash)		encap_flow_table;
    BVT(clib_bihash)		decap_flow_table;
    BVT(clib_bihash)		decap_flow_table_macsec;

    /*
     * These vectors keep track of which flow indices are allocated
     */
    void			**idx_flow[N_ETFS_FLOW_TYPES];

    /*
     * New thread structures - for 2020 performance/protocol
     *
     * This is a vector indexed by thread_index
     */
    etfs_thread_main_t		*workers_main;

    vlib_main_t			*vlib_main;
    struct vnet_main_t		*vnet_main;

    /* API message ID base */
    u16				msg_id_base;
    u8				encap_flow_count;
    u8				decap_flow_count;

    clib_spinlock_t		encap_flow_table_lock;

    /* global node index identifying which encrypt node to use */
    u32				macsec_encrypt_node_index;

    /* next index in etfs_output_node next[] of encrypt node to use */
    u32				macsec_encrypt_next_node_index;

    /* lock to protect allocations of the counter vectors and also to
     * protect accesses to the flow counters.
     */
    clib_spinlock_t		counter_lock;

    /*
     * global counters
     */
    vlib_simple_counter_main_t	global_scm[ETFS_GLOBAL_SCTR_N_COUNTERS];

    /*
     * Counters specific to a flow
     */
    vlib_simple_counter_main_t	 encap_scm[ETFS_ENCAP_SCTR_N_COUNTERS];
    vlib_simple_counter_main_t	 decap_scm[ETFS_DECAP_SCTR_N_COUNTERS];
    vlib_combined_counter_main_t encap_ccm[ETFS_ENCAP_CCTR_N_COUNTERS];
    vlib_combined_counter_main_t decap_ccm[ETFS_DECAP_CCTR_N_COUNTERS];

    vlib_log_class_t		log_class;
} etfs3_main_t;

extern etfs3_main_t		etfs3_main;

#define ETFS_N_OUTPUT_BYTE_CTR			10
#define ETFS_OUTPUT_BYTE_CTR_INTERVAL_SECS	10

typedef struct
{
    f64	fsecs;
    u64	packets;
    u64	bytes;
    u64 dues;
    u64 cputicks;
} etfs_tc_t;

/* encap flow state, 1 per flow */

/* new protocol/performance implementation */
typedef struct state_encap_flow_v2 {
    struct {
	SRING_RING_ANON(ETFS_TXQ_LOG2, u32)	q; /* Lockless rx->tx ring */
	u64		next_desired_tx_cputicks;
	u64		lastdue;/* last time a packet was supposed sent */
	etfs_zpool_t	*zpool;	/* zpool for output */
	elog_track_t	output_track;
	elog_track_t	zpool_track;
	elog_track_t	error_track;
	u16		output_gen;	/* debug */
	u64		next_desired_tx_output_byte_counter_cputicks;
	etfs_tc_t	*output_byte_counter_q;

	/*
	 * Keep a few internal counters for debugging that ARE NOT CLEARED
	 * via the API clear-counters function (sheesh).
	 */
	u64		c_out_pkts;
	u64		c_out_bytes;
	u64		c_out_dues;
    } output;	/* was encap_tx */

    struct {
	u64		next_desired_tx_cputicks;
	u16		pacer_gen;	/* debug */
    } pacer;

    struct {
	u32			bi_inprogress;
	u32			nsegs_inprogress;
	u32			uf_bytes;	/* user bytes in buffer */
	u32			space_avail;	/* avail in-progress space */
	etfs_zpool_t		*zpool;
	u32			ffc_inprogress;	/* debug */
	/*
	 * The fragment sequence numbers are distinct for default vs. express
	 * frames.
	 */
	u32			frag_seq_default;
	u32			frag_seq_express;
	u16			tf_seq_debug;
	iptfs_bufq		pacer_queue;		/* pacer input */
	iptfs_bufq_limit	pacer_queue_depth;	/* payload total */
	u32			rx_thread_index;
	elog_track_t		pacer_track;
	elog_track_t		zpool_track;
	elog_track_t		error_track;
    } encap;

    struct {
	/* flags indicating which nodes are activated for this flow */
	bool		node_running[ETFS_ENCAP_POLLER_COUNT];
	/* qualified by node_running */
	u32		thread_id[ETFS_ENCAP_POLLER_COUNT];
    } thread;

    struct {
	u16			index;

	bool			macsec_enabled : 1;
	bool			encap_no_pad_only : 1;
	bool			all_pad_trace : 1;
	bool			tx_port_is_dpdk : 1;
	bool			send_direct_bufs_only : 1;/*macsec||dpdk port*/

	u32			next_index;

	u8			ether_header[ETFS_MAX_ETHERNET_HEADER_SIZE];
	u8			ether_header_len;
	u16			framesize;	/* provisioned */
	u16			tx_mtu;		/* from interface */
	u32			tx_rate_bits_msec;
	u16			min_fragment;

	/* computed */
	u64			tx_interval_usec;
	u64			tx_interval_cputicks;
	u64			output_byte_counter_interval_cputicks;

	/* configured */
	u32			max_aggr_time_usec;

	/* computed from configured values */
	u64			max_aggr_time_bounded_usec;
	u32			max_queue_depth_bytes;

	u32			if_index_rx;
	u32			if_hw_index_rx;
	u32			if_sw_index_rx;
	u32			if_index_tx;

	u32			ipsec_sa_index;		/* if macsec_enabled */
    } config;

    /*
     * subordinate parts of an encap flow structure that are
     * dynamically-allocated and must be freed before the flow structure
     * is freed. We use these flags so we have a consistent way of
     * identifying what has been already allocated
     */
    struct {
	bool parent_flow_table_entry: 1;
	bool macsec_sa: 1;
	bool output_zpool: 1;
	bool encap_zpool: 1;
	bool encap_to_pacer_q: 1;

	bool encap_pacer_track_name: 1;
	bool encap_pacer_track_elog: 1;

	bool encap_zpool_track_name: 1;
	bool encap_zpool_track_elog: 1;

	bool encap_error_track_name: 1;
	bool encap_error_track_elog: 1;

	bool output_output_track_name: 1;
	bool output_output_track_elog: 1;

	bool output_zpool_track_name: 1;
	bool output_zpool_track_elog: 1;

	bool output_error_track_name: 1;
	bool output_error_track_elog: 1;

	bool output_byte_counter_q: 1;
    } allocated;

} state_encap_flow_v2_t ;

typedef struct {
    vlib_buffer_t			*fragment;
    u16					mtdu_offset;
    u16					db_length;	/* 1st pkt only */
    datablock_reassembly_cursor_t	cursor;
} datablock_reassembly_entry_t;

/* reassembly control block */
typedef struct {
    u32		sequence;
    u32		bi;
    bool	flag_valid : 1;
    bool	flag_initial : 1;
    bool	flag_final : 1;
} etfs_reasm_t;

typedef enum {
    NORMAL = 0,
    EXPRESS = 1,
    N_ETFS_FRAGMENT_STREAMS
} etfs_fragment_stream_type_t;


typedef struct state_decap_flow_v2 {
    struct {
	u32	if_index_rx;
	u32	if_index_tx;
	u32	if_hw_index_rx;	/* not needed? */
	u32	ipsec_sa_index;	/* if macsec_enabled */
	u32	tx_mtu;
	u16	index;
	u16	maxwin;
	bool	tx_port_is_dpdk : 1;
	bool	macsec_enabled : 1;
    } config;
    struct {
	u32	*rx;		/* per-flow temporary packet storage */
        u32	*send;		/* per-flow temporary packet storage */
        u32	*drop;		/* per-flow temporary packet storage */
	SRING_RING_ANON(ETFS_DDQ_LOG2, u32)	q; /* Lockless rx->tx ring */
	u32	rx_thread_index;
	u16	tf_seq_debug;
    } decoupler;
    struct {
	/* flags indicating which nodes are activated for this flow */
	bool		node_running[ETFS_DECAP_POLLER_COUNT];
	/* qualified by node_running */
	u32		thread_id[ETFS_DECAP_POLLER_COUNT];
    } thread;

    struct etfs_decap_reasm {
	etfs_reasm_t	*win;	/* vector of fragments to reassemble */
	u32		nextseq;/* 24b expected frag seq number (wraps) */
	u16		nextidx;/* slot of nextseq */
    } reasm[N_ETFS_FRAGMENT_STREAMS];	/* 0 = normal, 1 = express */

    struct {
	bool parent_flow_table_entry: 1;
    } allocated;
} state_decap_flow_v2_t;

typedef struct {
    vlib_main_t	*vlm;
    u16		framesize;
    u32		tx_rate_bits_msec;
    u32		max_aggr_time_usec;
    u32		rxport;
    u32		txport;
    u8		stea[6];
    u8		dtea[6];
    u32		worker_thread_index;	/* 0 = unspecified, >0 = specific */
    bool	all_pad_trace;		/* for debugging */
} etfs3_encap_new_arg_t;

extern int
etfs_encap_new(etfs3_encap_new_arg_t *a, macsec_sa_t *sa, int *error2);

typedef struct {
    vlib_main_t	*vlm;
    u32		rxport;
    u32		txport;
} etfs3_decap_new_arg_t;

extern int
etfs_decap_new(etfs3_decap_new_arg_t *a, macsec_sa_t *sa, int *error2);

extern int
etfs_encap_delete(vlib_main_t *vm, vnet_main_t *vnm, u32 rxport);

extern int
etfs_decap_delete(u32 rxport, bool is_macsec);

state_encap_flow_v2_t *
encap_flow_get(u16 encap_rxport);

state_decap_flow_v2_t *
decap_flow_get(
    u16		decap_rxport,	/* rx port of flow to look up */
    bool	encrypted);	/* selected encrypted/plain flow on this port */

extern void
etfs_output_byte_counter_q_init(state_encap_flow_v2_t *ef);

extern void
etfs_output_byte_counter_q_free(state_encap_flow_v2_t *ef);

extern u8 *
etfs_output_byte_counter_q_format(u8 *s, va_list *args);

#define ETFS3_PLUGIN_BUILD_VER "1.0"

#define etfs3_log(lvl, f, ...)		\
  do {						\
      vlib_log((lvl), etfs3_main.log_class, "%s: " f, \
               __func__, ##__VA_ARGS__);	\
  } while (0)

#include <plugins/etfs3/etfs_counter_funcs.h>

#ifdef __cplusplus
}
#endif

#endif /* included_etfs3_h */

/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

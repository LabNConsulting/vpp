/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_dpdk_h__
#define __included_dpdk_h__

/* $$$$ We should rename always_inline -> clib_always_inline */
#undef always_inline

#define ALLOW_EXPERIMENTAL_API

#include <rte_config.h>

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>
#include <rte_sched.h>
#include <rte_net.h>
#include <rte_bus_pci.h>
#include <rte_flow.h>

#include <vnet/devices/devices.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#include <vlib/pci/pci.h>
#include <vnet/flow/flow.h>

extern vnet_device_class_t dpdk_device_class;
extern vlib_node_registration_t dpdk_input_node;
extern vlib_node_registration_t admin_up_down_process_node;

#define foreach_dpdk_pmd          \
  _ ("net_thunderx", THUNDERX)    \
  _ ("net_e1000_em", E1000EM)     \
  _ ("net_e1000_igb", IGB)        \
  _ ("net_e1000_igb_vf", IGBVF)   \
  _ ("net_ixgbe", IXGBE)          \
  _ ("net_ixgbe_vf", IXGBEVF)     \
  _ ("net_i40e", I40E)            \
  _ ("net_i40e_vf", I40EVF)       \
  _ ("net_ice", ICE)              \
  _ ("net_iavf", IAVF)            \
  _ ("net_virtio", VIRTIO)        \
  _ ("net_enic", ENIC)            \
  _ ("net_vmxnet3", VMXNET3)      \
  _ ("AF_PACKET PMD", AF_PACKET)  \
  _ ("net_fm10k", FM10K)          \
  _ ("net_cxgbe", CXGBE)          \
  _ ("net_mlx4", MLX4)            \
  _ ("net_mlx5", MLX5)            \
  _ ("net_dpaa2", DPAA2)          \
  _ ("net_virtio_user", VIRTIO_USER) \
  _ ("net_vhost", VHOST_ETHER)    \
  _ ("net_ena", ENA)              \
  _ ("net_failsafe", FAILSAFE)    \
  _ ("net_liovf", LIOVF_ETHER)    \
  _ ("net_qede", QEDE)		  \
  _ ("net_netvsc", NETVSC)        \
  _ ("net_bnxt", BNXT)

typedef enum
{
  VNET_DPDK_PMD_NONE,
#define _(s,f) VNET_DPDK_PMD_##f,
  foreach_dpdk_pmd
#undef _
    VNET_DPDK_PMD_UNKNOWN,	/* must be last */
} dpdk_pmd_t;

typedef enum
{
  VNET_DPDK_PORT_TYPE_ETH_1G,
  VNET_DPDK_PORT_TYPE_ETH_2_5G,
  VNET_DPDK_PORT_TYPE_ETH_5G,
  VNET_DPDK_PORT_TYPE_ETH_10G,
  VNET_DPDK_PORT_TYPE_ETH_20G,
  VNET_DPDK_PORT_TYPE_ETH_25G,
  VNET_DPDK_PORT_TYPE_ETH_40G,
  VNET_DPDK_PORT_TYPE_ETH_50G,
  VNET_DPDK_PORT_TYPE_ETH_56G,
  VNET_DPDK_PORT_TYPE_ETH_100G,
  VNET_DPDK_PORT_TYPE_ETH_SWITCH,
  VNET_DPDK_PORT_TYPE_AF_PACKET,
  VNET_DPDK_PORT_TYPE_ETH_VF,
  VNET_DPDK_PORT_TYPE_VIRTIO_USER,
  VNET_DPDK_PORT_TYPE_VHOST_ETHER,
  VNET_DPDK_PORT_TYPE_FAILSAFE,
  VNET_DPDK_PORT_TYPE_NETVSC,
  VNET_DPDK_PORT_TYPE_UNKNOWN,
} dpdk_port_type_t;

typedef uint16_t dpdk_portid_t;

#define foreach_dpdk_device_flags \
  _( 0, ADMIN_UP, "admin-up") \
  _( 1, PROMISC, "promisc") \
  _( 2, PMD, "pmd") \
  _( 3, PMD_INIT_FAIL, "pmd-init-fail") \
  _( 4, MAYBE_MULTISEG, "maybe-multiseg") \
  _( 5, HAVE_SUBIF, "subif") \
  _( 9, TX_OFFLOAD, "tx-offload") \
  _(10, INTEL_PHDR_CKSUM, "intel-phdr-cksum") \
  _(11, RX_FLOW_OFFLOAD, "rx-flow-offload") \
  _(12, RX_IP4_CKSUM, "rx-ip4-cksum")

enum
{
#define _(a, b, c) DPDK_DEVICE_FLAG_##b = (1 << a),
  foreach_dpdk_device_flags
#undef _
};

typedef struct
{
  u32 flow_index;
  u32 mark;
  struct rte_flow *handle;
} dpdk_flow_entry_t;

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} dpdk_flow_lookup_entry_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8 buffer_pool_index;
} dpdk_rx_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lock;
} dpdk_tx_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  dpdk_rx_queue_t *rx_queues;
  dpdk_tx_queue_t *tx_queues;

  /* Instance ID to access internal device array. */
  u32 device_index;

  u32 hw_if_index;
  u32 sw_if_index;

  /* next node index if we decide to steal the rx graph arc */
  u32 per_interface_next_index;

  u16 rx_q_used;
  u16 tx_q_used;
  u16 flags;

  /* DPDK device port number */
  dpdk_portid_t port_id;
  dpdk_pmd_t pmd:8;
  i8 cpu_socket;

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u16 nb_tx_desc;
  u16 nb_rx_desc;

  u8 *name;
  u8 *interface_name_suffix;

  /* number of sub-interfaces */
  u16 num_subifs;

  /* PMD related */
  struct rte_eth_conf port_conf;
  struct rte_eth_txconf tx_conf;

  /* flow related */
  u32 supported_flow_actions;
  dpdk_flow_entry_t *flow_entries;	/* pool */
  dpdk_flow_lookup_entry_t *flow_lookup_entries;	/* pool */
  u32 *parked_lookup_indexes;	/* vector */
  u32 parked_loop_count;
  struct rte_flow_error last_flow_error;

  /* af_packet instance number */
  u16 af_packet_instance_num;

  struct rte_eth_link link;
  f64 time_last_link_update;

  struct rte_eth_stats stats;
  struct rte_eth_stats last_stats;
  struct rte_eth_xstat *xstats;
  f64 time_last_stats_update;
  dpdk_port_type_t port_type;

  /* mac address */
  u8 *default_mac_address;

  /* error string */
  clib_error_t *errors;
} dpdk_device_t;

#define DPDK_STATS_POLL_INTERVAL      (10.0)
#define DPDK_MIN_STATS_POLL_INTERVAL  (0.001)	/* 1msec */

#define DPDK_LINK_POLL_INTERVAL       (3.0)
#define DPDK_MIN_LINK_POLL_INTERVAL   (0.001)	/* 1msec */

#define foreach_dpdk_device_config_item \
  _ (num_rx_queues) \
  _ (num_tx_queues) \
  _ (num_rx_desc) \
  _ (num_tx_desc) \
  _ (rss_fn)

typedef struct
{
  vlib_pci_addr_t pci_addr;
  u8 *name;
  u8 is_blacklisted;
  u8 vlan_strip_offload;
#define DPDK_DEVICE_VLAN_STRIP_DEFAULT 0
#define DPDK_DEVICE_VLAN_STRIP_OFF 1
#define DPDK_DEVICE_VLAN_STRIP_ON  2

#define _(x) uword x;
    foreach_dpdk_device_config_item
#undef _
    clib_bitmap_t * workers;
  u8 tso;
  u8 *devargs;
  clib_bitmap_t *rss_queues;

#define DPDK_DEVICE_TSO_DEFAULT 0
#define DPDK_DEVICE_TSO_OFF 1
#define DPDK_DEVICE_TSO_ON  2
} dpdk_device_config_t;

typedef struct
{

  /* Config stuff */
  u8 **eal_init_args;
  u8 *eal_init_args_str;
  u8 *uio_driver_name;
  u8 no_multi_seg;
  u8 enable_tcp_udp_checksum;
  u8 no_tx_checksum_offload;

  /* Required config parameters */
  u8 coremask_set_manually;
  u8 nchannels_set_manually;
  u32 coremask;
  u32 nchannels;
  u32 num_crypto_mbufs;

  /*
   * format interface names ala xxxEthernet%d/%d/%d instead of
   * xxxEthernet%x/%x/%x.
   */
  u8 interface_name_format_decimal;

  /* per-device config */
  dpdk_device_config_t default_devconf;
  dpdk_device_config_t *dev_confs;
  uword *device_config_index_by_pci_addr;

  /* devices blacklist by pci vendor_id, device_id */
  u32 *blacklist_by_pci_vendor_and_device;

} dpdk_config_main_t;

extern dpdk_config_main_t dpdk_config_main;

#define DPDK_RX_BURST_SZ VLIB_FRAME_SIZE

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct rte_mbuf *mbufs[DPDK_RX_BURST_SZ];
  u32 buffers[DPDK_RX_BURST_SZ];
  u16 next[DPDK_RX_BURST_SZ];
  u16 etype[DPDK_RX_BURST_SZ];
  u16 flags[DPDK_RX_BURST_SZ];
  vlib_buffer_t buffer_template;
} dpdk_per_thread_data_t;

typedef struct
{

  /* Devices */
  dpdk_device_t *devices;
  dpdk_per_thread_data_t *per_thread_data;

  /* buffer flags template, configurable to enable/disable tcp / udp cksum */
  u32 buffer_flags_template;

  /*
   * flag indicating that a posted admin up/down
   * (via post_sw_interface_set_flags) is in progress
   */
  u8 admin_up_down_in_progress;

  /* control interval of dpdk link state and stat polling */
  f64 link_state_poll_interval;
  f64 stat_poll_interval;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  dpdk_config_main_t *conf;

  /* API message ID base */
  u16 msg_id_base;

  /* logging */
  vlib_log_class_t log_default;
} dpdk_main_t;

extern dpdk_main_t dpdk_main;

typedef struct
{
  u32 buffer_index;
  struct rte_mbuf mb;
  vlib_buffer_t buffer;
} dpdk_tx_trace_chain_t;

typedef struct
{
  u32 buffer_index;
  u16 device_index;
  u8 queue_index;
  u8 tail_length;
  struct rte_mbuf mb;
  /* Copy of VLIB buffer; packet data stored in pre_data. */
  vlib_buffer_t buffer;
  dpdk_tx_trace_chain_t chains[0];
} dpdk_tx_trace_t;

typedef struct
{
  u32 buffer_index;
  u16 device_index;
  u16 queue_index;
  struct rte_mbuf mb;
  vlib_buffer_t buffer;		/* Copy of VLIB buffer; pkt data stored in pre_data. */
  u8 data[256];			/* First 256 data bytes, used for hexdump */
} dpdk_rx_trace_t;

void dpdk_device_setup (dpdk_device_t * xd);
void dpdk_device_start (dpdk_device_t * xd);
void dpdk_device_stop (dpdk_device_t * xd);
int dpdk_port_state_callback (dpdk_portid_t port_id,
			      enum rte_eth_event_type type,
			      void *param, void *ret_param);

#define foreach_dpdk_error						\
  _(NONE, "no error")							\
  _(RX_PACKET_ERROR, "Rx packet errors")				\
  _(RX_BAD_FCS, "Rx bad fcs")						\
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")				\
  _(RX_ALLOC_FAIL, "rx buf alloc from free list failed")		\
  _(RX_ALLOC_NO_PHYSMEM, "rx buf alloc failed no physmem")		\
  _(RX_ALLOC_DROP_PKTS, "rx packets dropped due to alloc error")

typedef enum
{
#define _(f,s) DPDK_ERROR_##f,
  foreach_dpdk_error
#undef _
    DPDK_N_ERROR,
} dpdk_error_t;

#define dpdk_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, dpdk_main.log_default, __VA_ARGS__)
#define dpdk_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, dpdk_main.log_default, __VA_ARGS__)
#define dpdk_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, dpdk_main.log_default, __VA_ARGS__)
#define dpdk_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, dpdk_main.log_default, __VA_ARGS__)

void dpdk_update_link_state (dpdk_device_t * xd, f64 now);

#define foreach_dpdk_rss_hf                    \
  _(0, ETH_RSS_FRAG_IPV4,           "ipv4-frag")    \
  _(1, ETH_RSS_NONFRAG_IPV4_TCP,    "ipv4-tcp")     \
  _(2, ETH_RSS_NONFRAG_IPV4_UDP,    "ipv4-udp")     \
  _(3, ETH_RSS_NONFRAG_IPV4_SCTP,   "ipv4-sctp")    \
  _(4, ETH_RSS_NONFRAG_IPV4_OTHER,  "ipv4-other")   \
  _(5, ETH_RSS_IPV4,                "ipv4")         \
  _(6, ETH_RSS_IPV6_TCP_EX,         "ipv6-tcp-ex")  \
  _(7, ETH_RSS_IPV6_UDP_EX,         "ipv6-udp-ex")  \
  _(8, ETH_RSS_FRAG_IPV6,           "ipv6-frag")    \
  _(9, ETH_RSS_NONFRAG_IPV6_TCP,    "ipv6-tcp")     \
  _(10, ETH_RSS_NONFRAG_IPV6_UDP,   "ipv6-udp")     \
  _(11, ETH_RSS_NONFRAG_IPV6_SCTP,  "ipv6-sctp")    \
  _(12, ETH_RSS_NONFRAG_IPV6_OTHER, "ipv6-other")   \
  _(13, ETH_RSS_IPV6_EX,            "ipv6-ex")      \
  _(14, ETH_RSS_IPV6,               "ipv6")         \
  _(15, ETH_RSS_L2_PAYLOAD,         "l2-payload")   \
  _(16, ETH_RSS_PORT,               "port")         \
  _(17, ETH_RSS_VXLAN,              "vxlan")        \
  _(18, ETH_RSS_GENEVE,             "geneve")       \
  _(19, ETH_RSS_NVGRE,              "nvgre")        \
  _(20, ETH_RSS_GTPU,               "gtpu")         \
  _(60, ETH_RSS_L4_DST_ONLY,        "l4-dst-only")  \
  _(61, ETH_RSS_L4_SRC_ONLY,        "l4-src-only")  \
  _(62, ETH_RSS_L3_DST_ONLY,        "l3-dst-only")  \
  _(63, ETH_RSS_L3_SRC_ONLY,        "l3-src-only")

format_function_t format_dpdk_device_name;
format_function_t format_dpdk_device;
format_function_t format_dpdk_device_errors;
format_function_t format_dpdk_tx_trace;
format_function_t format_dpdk_rx_trace;
format_function_t format_dpdk_rte_mbuf;
format_function_t format_dpdk_rx_rte_mbuf;
format_function_t format_dpdk_flow;
format_function_t format_dpdk_rss_hf_name;
format_function_t format_dpdk_rx_offload_caps;
format_function_t format_dpdk_tx_offload_caps;
vnet_flow_dev_ops_function_t dpdk_flow_ops_fn;

format_function_t format_chained_indirect_buffer;
format_function_t format_chained_rte_mbuf;

clib_error_t *unformat_rss_fn (unformat_input_t * input, uword * rss_fn);

struct rte_pci_device *dpdk_get_pci_device (const struct rte_eth_dev_info
					    *info);
void dpdk_cli_reference (void);

#if CLI_DEBUG
int dpdk_buffer_validate_trajectory_all (u32 * uninitialized);
void dpdk_buffer_poison_trajectory_all (void);
#endif

#endif /* __included_dpdk_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

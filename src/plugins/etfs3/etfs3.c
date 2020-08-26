/*
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
/**
 * @file
 * @brief Sample Plugin, plugin API / trace / CLI handling.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vnet/macsec/macsec.h>
#include <vnet/macsec/macsec_format.h>
#include <vnet/ipsec/ipsec.h>
#include <etfs3/etfs3.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <etfs3/etfs3_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <etfs3/etfs3_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <etfs3/etfs3_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <etfs3/etfs3_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <etfs3/etfs3_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_etfs3_plugin_api_msg				\
_(ETFS3_ENCAP_ADD, etfs3_encap_add)				\
_(ETFS3_DECAP_ADD, etfs3_decap_add)				\
_(ETFS3_ENCAP_DELETE, etfs3_encap_delete)			\
_(ETFS3_DECAP_DELETE, etfs3_decap_delete)			\
_(ETFS3_ENCAP_FLOW_DUMP, etfs3_encap_flow_dump)			\
_(ETFS3_DECAP_FLOW_DUMP, etfs3_decap_flow_dump)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = ETFS3_PLUGIN_BUILD_VER,
    .description = "ETFS3 Plugin",
};
/* *INDENT-ON* */

/**
 * @brief Enable/disable encap generation on the interface (testing)
 *
 * Action function shared between message handler and debug CLI.
 */
static clib_error_t *
encap_add_command_fn(
    vlib_main_t		*vm,
    unformat_input_t	*_input,
    vlib_cli_command_t	*cmd)
{
    etfs3_encap_new_arg_t	arg;
    int				set_stea = 0;
    int				set_dtea = 0;
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_sw_interface_t		*sw;
#endif
    int				rv = 0;
    int				error2 = 0;
    macsec_sa_t			macsec_sa;
    int				set_macsec = 0;

    arg.vlm			= vm;
    arg.framesize		= ETFS_MTDU_FRAME_SIZE_DEFAULT;
    arg.tx_rate_bits_msec	= ETFS_TX_RATE_BITSPERMSEC_DEFAULT;
    arg.max_aggr_time_usec	= ETFS_MAX_AGGR_TIME_USEC_DEFAULT;
    arg.rxport			= (u16)~0;
    arg.txport			= (u16)~0;
    arg.worker_thread_index	= 0;
    arg.all_pad_trace		= false;

    /* Get a line of input. */
    unformat_input_t _line_input, *input = &_line_input;
    if (!unformat_user (_input, unformat_line_input, input))
	return 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat(input, "rx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &arg.rxport))
	    ;
	else if (unformat(input, "tx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &arg.txport))
	    ;
	else if (unformat(input, "fs %u", &arg.framesize))
	    ;
	else if (unformat(input, "rate %u", &arg.tx_rate_bits_msec))
	    ;
	else if (unformat(input, "maxagg %u", &arg.max_aggr_time_usec))
	    ;
	else if (unformat(input, "stea %U", unformat_ethernet_address, arg.stea))
	    set_stea = 1;
	else if (unformat(input, "dtea %U", unformat_ethernet_address, arg.dtea))
	    set_dtea = 1;
	else if (unformat(input, "worker %u", &arg.worker_thread_index))
	    ;
	else if (unformat(input, "all-pad-trace %u", &rv))
	    arg.all_pad_trace = rv;
	else if (unformat(input, "macsec %U",
	    unformat_etfs_macsec_sa_config, &macsec_sa))
	    set_macsec = 1;
	else
	    return clib_error_return (0, "parse error: '%U'",
		format_unformat_error, input);
    }
    unformat_free(input);

    if (arg.rxport == (u16)~0)
	return clib_error_return (0, "Please specify a receive interface");
    if (arg.txport == (u16)~0)
	return clib_error_return (0, "Please specify a transmit interface");
    if (!set_dtea)
	return clib_error_return (0, "Please specify a dst tx ethernet addr");

    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	arg.rxport)) {
	    return clib_error_return (0,
		"Invalid rx interface, only works on physical ports");
    }
    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	arg.txport)) {
	    return clib_error_return (0,
		"Invalid tx interface, only works on physical ports");
    }

#if ETFS_PORTS_PHYSICAL_ONLY
    /* Not a physical port? */
    sw = vnet_get_sw_interface (etfs3_main.vnet_main, arg.rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid rx interface, only works on physical ports");

    sw = vnet_get_sw_interface (etfs3_main.vnet_main, arg.txport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid tx interface, only works on physical ports");
#endif /* ETFS_PORTS_PHYSICAL_ONLY */

    /*
     * Validate macsec configuration
     */
    if (set_macsec) {
	/* Since this is encap configuration, macsec SA should be outbound */
	if (macsec_sa.flags & MACSEC_SA_FLAG_IS_INBOUND) {
	    return clib_error_return (0,
		"rx-crypto-key valid only for decap; specify "
		"tx-crypto-key instead");
	}
	if ((macsec_sa.crypto_alg != MACSEC_CRYPTO_ALG_NONE) &&
	    (! macsec_sa.crypto_key.len)) {

	    return clib_error_return (0, "Missing tx-crypto-key");
	}

	clib_memcpy(macsec_sa.ether_addr, arg.stea, sizeof(macsec_sa.ether_addr));

	macsec_sa.if_index = arg.txport;
    }

    /* If no source address provided, tell etfs_encap_new() to use the
     * address found on the tx interface
     */
    if (!set_stea)
	memset(arg.stea, 0, sizeof(arg.stea));

    rv = etfs_encap_new(&arg, (set_macsec? &macsec_sa: NULL), &error2);

    if (!rv)
	return 0;

    switch (rv) {
    case VNET_API_ERROR_TABLE_TOO_BIG:
	return clib_error_return (0,
	    "Too many encap flows");
    case VNET_API_ERROR_NO_SUCH_NODE:
	return clib_error_return (0,
	    "Internal error: can't locate rx node");
    case VNET_API_ERROR_NO_SUCH_NODE2:
	return clib_error_return (0,
	    "Config error: can't locate %s node",
	    (set_macsec? "macsec encrypt": "interface output"));
    case VNET_API_ERROR_INVALID_VALUE:
	return clib_error_return (0,
	    "Framesize too big for transmit interface MTU");
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
	return clib_error_return (0,
	    "Receive interface already has encap flow configured");
    case VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH:
	return clib_error_return (0,
	    "Invalid tx interface hardware address legnth");
    case VNET_API_ERROR_INVALID_INTERFACE:
	return clib_error_return (0, "Unknown interface");
    case VNET_API_ERROR_INIT_FAILED:
	return clib_error_return (0, "Can't init pad buffer");
    case VNET_API_ERROR_INVALID_WORKER:
	return clib_error_return (0, "Invalid worker thread index");
    case VNET_API_ERROR_FEATURE_DISABLED:
	return clib_error_return (0,
	    "macsec requested but not available");
    case VNET_API_ERROR_SYSCALL_ERROR_1:
	return clib_error_return (0, "Can't create MACSEC SA: %U",
	    format_vnet_api_errno, error2);
    }

    return clib_error_return (0, "unknown etfs_encap_new() error: %d", rv);
}

/**
 * @brief CLI command to enable/disable the etfs3 encap plugin.
 */
VLIB_CLI_COMMAND (encap_add_command, static) = {
    .path = "etfs3 encap add",
    .short_help =
    "etfs3 encap add rx <ifname> tx <ifname> [fs <len>] [rate <bits/msec>] [maxagg <usec>] [stea <ethaddr>] dtea <ethaddr> [worker <thread-id>] [macsec crypto-alg aes-gcm-256|aes-gcm-128 local-crypto-key <key>]",
    .function = encap_add_command_fn,
};

/**
 * @brief Plugin API message handler.
 */
static void vl_api_etfs3_encap_add_t_handler
(vl_api_etfs3_encap_add_t *mp)
{
    vl_api_etfs3_encap_add_reply_t	*rmp;
    etfs3_main_t			*sm = &etfs3_main;
    etfs3_encap_new_arg_t		arg;
    int					rv = 0;

    arg.framesize = mp->framesize;
    arg.tx_rate_bits_msec = mp->tx_rate_bits_msec;
    arg.max_aggr_time_usec = mp->max_aggr_time_usec;
    arg.rxport = mp->rxport;
    arg.txport = mp->txport;
    memcpy(arg.stea, mp->stea, sizeof(arg.stea));
    memcpy(arg.dtea, mp->dtea, sizeof(arg.dtea));
    arg.vlm = sm->vlib_main;

    rv = etfs_encap_new (&arg, NULL, NULL);

    REPLY_MACRO(VL_API_ETFS3_ENCAP_ADD_REPLY);
}

/**
 * @brief Enable/disable encap generation on the interface (testing)
 *
 * Action function shared between message handler and debug CLI.
 */
static clib_error_t *
encap_delete_command_fn(
    vlib_main_t		*vm,
    unformat_input_t	*_input,
    vlib_cli_command_t	*cmd)
{
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_sw_interface_t		*sw;
#endif
    int				rv = 0;
    u16				rxport = (u16)~0;

    /* Get a line of input. */
    unformat_input_t _line_input, *input = &_line_input;
    if (!unformat_user (_input, unformat_line_input, input))
	return 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat(input, "rx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &rxport))
	    ;
	else
	    return clib_error_return (0, "parse error: '%U'",
		format_unformat_error, input);
    }
    unformat_free(input);

    if (rxport == (u16)~0)
	return clib_error_return (0, "Please specify a receive interface");

    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	rxport)) {
	    return clib_error_return (0,
		"Invalid rx interface, only works on physical ports");
    }

#if ETFS_PORTS_PHYSICAL_ONLY
    /* Not a physical port? */
    sw = vnet_get_sw_interface (etfs3_main.vnet_main, rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid rx interface, only works on physical ports");
#endif /* ETFS_PORTS_PHYSICAL_ONLY */

    rv = etfs_encap_delete(vm, etfs3_main.vnet_main, rxport);

    if (!rv)
	return 0;

    switch (rv) {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
	return clib_error_return (0,
	    "No encap flow configured on specified receive interface");
    }

    return clib_error_return (0, "unknown etfs_encap_delete() error: %d", rv);
}

/**
 * @brief CLI command to enable/disable the etfs3 encap plugin.
 */
VLIB_CLI_COMMAND (encap_delete_command, static) = {
    .path = "etfs3 encap delete",
    .short_help =
    "etfs3 encap delete rx <ifname>",
    .function = encap_delete_command_fn,
};

/**
 * @brief Plugin API message handler.
 */
static void vl_api_etfs3_encap_delete_t_handler
(vl_api_etfs3_encap_delete_t *mp)
{
    vl_api_etfs3_encap_delete_reply_t	*rmp;
    etfs3_main_t			*sm = &etfs3_main;
    int					rv = 0;

    rv = etfs_encap_delete(sm->vlib_main, sm->vnet_main, mp->rxport);

    REPLY_MACRO(VL_API_ETFS3_ENCAP_DELETE_REPLY);
}


/**
 * @brief Enable/disable decap generation on the interface (testing)
 *
 * Action function shared between message handler and debug CLI.
 */
static clib_error_t *
decap_add_command_fn(
    vlib_main_t		*vm,
    unformat_input_t	*_input,
    vlib_cli_command_t	*cmd)
{
    etfs3_decap_new_arg_t	arg;
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_sw_interface_t		*sw;
#endif
    int				rv = 0;
    macsec_sa_t			macsec_sa;
    u8				stea[6];
    int				set_macsec = 0;
    int				set_stea = 0;
    int				error2;

    arg.vlm			= vm;
    arg.rxport			= (u16)~0;
    arg.txport			= (u16)~0;

    /* Get a line of input. */
    unformat_input_t _line_input, *input = &_line_input;
    if (!unformat_user (_input, unformat_line_input, input))
	return 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat(input, "rx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &arg.rxport))
	    ;
	else if (unformat(input, "tx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &arg.txport))
	    ;
	else if (unformat(input, "macsec %U",
	    unformat_etfs_macsec_sa_config, &macsec_sa))
	    set_macsec = 1;
	/* NB stea is required for macsec */
	else if (unformat(input, "stea %U", unformat_ethernet_address, stea))
	    set_stea = 1;
	else
	    return clib_error_return (0, "parse error: '%U'",
		format_unformat_error, input);
    }
    unformat_free(input);

    if (arg.rxport == (u16)~0)
	return clib_error_return (0, "Please specify a receive interface");
    if (arg.txport == (u16)~0)
	return clib_error_return (0, "Please specify a transmit interface");

    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	arg.rxport)) {
	    return clib_error_return (0,
		"Invalid rx interface, only works on physical ports");
    }
    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	arg.txport)) {
	    return clib_error_return (0,
		"Invalid tx interface, only works on physical ports");
    }

#if ETFS_PORTS_PHYSICAL_ONLY
    /* Not a physical port? */
    sw = vnet_get_sw_interface (etfs3_main.vnet_main, arg.rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid rx interface, only works on physical ports");

    sw = vnet_get_sw_interface (etfs3_main.vnet_main, arg.txport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid tx interface, only works on physical ports");
#endif

    /*
     * Validate macsec configuration
     */
    if (set_macsec) {
	if (!set_stea) {
	    return clib_error_return (0,
		"Missing source tunnel ethernet address");
	}

	clib_memcpy(macsec_sa.ether_addr, stea, sizeof(macsec_sa.ether_addr));

	/* Since this is decap configuration, macsec SA should be inbound */
	if (!(macsec_sa.flags & MACSEC_SA_FLAG_IS_INBOUND)) {
	    return clib_error_return (0,
		"tx-crypto-key valid only for encap; specify "
		"rx-crypto-key instead");
	}
	if ((macsec_sa.crypto_alg != MACSEC_CRYPTO_ALG_NONE) &&
	    (! macsec_sa.crypto_key.len)) {

	    return clib_error_return (0, "Missing tx-crypto-key");
	}

	macsec_sa.if_index = arg.rxport;
    }

    rv = etfs_decap_new(&arg, (set_macsec? &macsec_sa: NULL), &error2);

    switch (rv) {
    case 0:
	break;
    case VNET_API_ERROR_TABLE_TOO_BIG:
	return clib_error_return (0,
	    "Too many decap flows");
    case VNET_API_ERROR_SYSCALL_ERROR_1:
	return clib_error_return (0,
	    "Can't create MACSEC SA: %U", format_vnet_api_errno, error2);
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
	return clib_error_return (0,
	    "Already handling received packets on this interface");
    case VNET_API_ERROR_FEATURE_DISABLED:
	return clib_error_return (0,
	    "macsec requested but not available");
    default:
	return clib_error_return (0,
	    "unknown etfs_decap_new() error");
    }

    return 0;
}

/**
 * @brief CLI command to enable/disable the etfs3 decap plugin.
 */
VLIB_CLI_COMMAND (decap_add_command, static) = {
    .path = "etfs3 decap add",
    .short_help =
    "etfs3 decap add rx <ifname> tx <ifname>",
    .function = decap_add_command_fn,
};

/**
 * @brief Plugin API message handler.
 */
static void vl_api_etfs3_decap_add_t_handler
(vl_api_etfs3_decap_add_t *mp)
{
    vl_api_etfs3_decap_add_reply_t	*rmp;
    etfs3_main_t			*sm = &etfs3_main;
    etfs3_decap_new_arg_t		arg;
    int					rv = 0;

    arg.rxport = mp->rxport;
    arg.txport = mp->txport;
    arg.vlm = etfs3_main.vlib_main;

    rv = etfs_decap_new (&arg, NULL, NULL);

    REPLY_MACRO(VL_API_ETFS3_DECAP_ADD_REPLY);
}

/**
 * @brief Enable/disable decap generation on the interface (testing)
 *
 * Action function shared between message handler and debug CLI.
 */
static clib_error_t *
decap_delete_command_fn(
    vlib_main_t		*vm,
    unformat_input_t	*_input,
    vlib_cli_command_t	*cmd)
{
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_sw_interface_t		*sw;
#endif
    int				rv = 0;
    bool			is_macsec = false;

    u16				rxport = (u16)~0;

    /* Get a line of input. */
    unformat_input_t _line_input, *input = &_line_input;
    if (!unformat_user (_input, unformat_line_input, input))
	return 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat(input, "rx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &rxport))
	    ;
	else if (unformat(input, "macsec"))
	    is_macsec = true;
	else
	    return clib_error_return (0, "parse error: '%U'",
		format_unformat_error, input);
    }
    unformat_free(input);

    if (rxport == (u16)~0)
	return clib_error_return (0, "Please specify a receive interface");

    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	rxport)) {
	    return clib_error_return (0,
		"Invalid rx interface, only works on physical ports");
    }

#if ETFS_PORTS_PHYSICAL_ONLY
    /* Not a physical port? */
    sw = vnet_get_sw_interface (etfs3_main.vnet_main, rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid rx interface, only works on physical ports");
#endif

    /*
     * Validate macsec configuration
     */

    rv = etfs_decap_delete(rxport, is_macsec);

    switch (rv) {
    case 0:
	break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
	return clib_error_return (0,
	    "No decap flow configured on specified receive interface");
    default:
	return clib_error_return (0,
	    "unknown etfs_decap_delete() error");
    }

    return 0;
}

/**
 * @brief CLI command to enable/disable the etfs3 decap plugin.
 */
VLIB_CLI_COMMAND (decap_delete_command, static) = {
    .path = "etfs3 decap delete",
    .short_help =
    "etfs3 decap delete rx <ifname> [macsec]",
    .function = decap_delete_command_fn,
};

/**
 * @brief Plugin API message handler.
 */
static void vl_api_etfs3_decap_delete_t_handler
(vl_api_etfs3_decap_delete_t *mp)
{
    vl_api_etfs3_decap_delete_reply_t	*rmp;
    etfs3_main_t			*sm = &etfs3_main;
    int					rv = 0;

    rv = etfs_decap_delete (mp->rxport, mp->is_macsec);

    REPLY_MACRO(VL_API_ETFS3_DECAP_DELETE_REPLY);
}

struct dump_etfs_callback_arg {
    vpe_api_main_t *am;
    vl_api_registration_t *rp;
    u32 context;
    u16 index;
};

static void
__send_etfs3_encap_flow_details(
    vpe_api_main_t *am,
    vl_api_registration_t *rp,
    const state_encap_flow_v2_t * const f,
    u32 context)
{
    vl_api_etfs3_encap_flow_details_t *mp = vl_msg_api_alloc(sizeof (*mp));

    clib_memset(mp, 0, sizeof (*mp));
    mp->_vl_msg_id = clib_net_to_host_u16(etfs3_main.msg_id_base +
			   VL_API_ETFS3_ENCAP_FLOW_DETAILS);
    mp->context = context;
    mp->framesize = clib_host_to_net_u32(f->config.framesize);
    mp->tx_rate_bits_msec = clib_host_to_net_u32(f->config.tx_rate_bits_msec);
    mp->max_aggr_time_usec = clib_host_to_net_u32(f->config.max_aggr_time_usec);
    mp->rx_sw_if_index = clib_host_to_net_u32(f->config.if_index_rx);
    mp->tx_sw_if_index = clib_host_to_net_u32(f->config.if_index_tx);
    mp->index = clib_host_to_net_u16(f->config.index);
    mp->ipsec_sa_index = clib_host_to_net_u32(f->config.ipsec_sa_index);
    mp->macsec_enabled = clib_host_to_net_u32(!!(u32)f->config.macsec_enabled);
    memcpy(mp->stea, f->config.ether_header + 6, sizeof(mp->stea));
    memcpy(mp->dtea, f->config.ether_header + 0, sizeof(mp->dtea));

    vl_api_send_msg(rp, (u8 *) mp);
}

static int
send_etfs3_encap_flow_details(
    BVT(clib_bihash_kv) * hash,
    void *_arg)
{
    struct dump_etfs_callback_arg *arg = _arg;
    const state_encap_flow_v2_t * const flow =
	(const state_encap_flow_v2_t * const)hash->value;

    if (arg->index == (u16)~0 || arg->index == flow->config.index)
	__send_etfs3_encap_flow_details(arg->am, arg->rp, flow, arg->context);

    return (BIHASH_WALK_CONTINUE);
}

/**
 * @brief Plugin API message handler.
 */
static void vl_api_etfs3_encap_flow_dump_t_handler
(vl_api_etfs3_encap_flow_dump_t  *mp)
{
    vpe_api_main_t *am = &vpe_api_main;
    vl_api_registration_t *rp;
    struct dump_etfs_callback_arg arg;

    rp = vl_api_client_index_to_registration(mp->client_index);
    arg.am = am;
    arg.rp = rp;
    arg.context = mp->context;
    arg.index = clib_net_to_host_u16(mp->index);

    BV(clib_bihash_foreach_key_value_pair)(&etfs3_main.encap_flow_table,
					   send_etfs3_encap_flow_details,
					   &arg);
}

static void
__send_etfs3_decap_flow_details(
    vpe_api_main_t *am,
    vl_api_registration_t *rp,
    const state_decap_flow_v2_t * const f,
    u32 context)
{
    vl_api_etfs3_decap_flow_details_t *mp = vl_msg_api_alloc(sizeof (*mp));
    clib_memset(mp, 0, sizeof (*mp));
    mp->_vl_msg_id = clib_net_to_host_u16(etfs3_main.msg_id_base +
			   VL_API_ETFS3_DECAP_FLOW_DETAILS);
    mp->context = context;
    mp->rx_sw_if_index = clib_host_to_net_u32(f->config.if_index_rx);
    mp->tx_sw_if_index = clib_host_to_net_u32(f->config.if_index_tx);
    mp->index = clib_host_to_net_u16(f->config.index);
    mp->ipsec_sa_index = clib_host_to_net_u32(f->config.ipsec_sa_index);
    mp->macsec_enabled = clib_host_to_net_u32(!!(u32)f->config.macsec_enabled);

    vl_api_send_msg(rp, (u8 *) mp);
}

static int
send_etfs3_decap_flow_details(
    BVT(clib_bihash_kv) * hash,
    void *_arg)
{
    struct dump_etfs_callback_arg *arg = _arg;
    const state_decap_flow_v2_t * const flow =
	(const state_decap_flow_v2_t * const)hash->value;

    if (arg->index == (u16)~0 || arg->index == flow->config.index)
	__send_etfs3_decap_flow_details(arg->am, arg->rp, flow, arg->context);

    return (BIHASH_WALK_CONTINUE);
}

/**
 * @brief Plugin API message handler.
 */
static void vl_api_etfs3_decap_flow_dump_t_handler
(vl_api_etfs3_decap_flow_dump_t  *mp)
{
    vpe_api_main_t *am = &vpe_api_main;
    vl_api_registration_t *rp;
    struct dump_etfs_callback_arg arg;

    rp = vl_api_client_index_to_registration(mp->client_index);
    arg.am = am;
    arg.rp = rp;
    arg.context = mp->context;
    arg.index = clib_net_to_host_u16(mp->index);

    BV(clib_bihash_foreach_key_value_pair)(&etfs3_main.decap_flow_table,
					   send_etfs3_decap_flow_details,
					   &arg);
    BV(clib_bihash_foreach_key_value_pair)(&etfs3_main.decap_flow_table_macsec,
					   send_etfs3_decap_flow_details,
					   &arg);
}

struct format_etfs_callback_results {
    u8 *str;
    u16 index;
};

struct format_etfs_callback_arg {
    struct format_etfs_callback_results *resv;
    u8 **str;
    u16 index;
    int macsec;
};

#if ETFS_PORTS_PHYSICAL_ONLY
static u8 *
format_etfs3_hw_itf(
    u32 idx,
    _Bool is_rx,
    const u8 * const addr)
{
    vnet_main_t *vnm = vnet_get_main ();
    vnet_hw_interface_t *hi;
    vnet_hw_interface_class_t *hw_class;
    u8 *str;

    hi = vnet_get_hw_interface (vnm, idx);
    if (hi == NULL)
	return NULL;

    hw_class = vnet_get_hw_interface_class (vnm, hi->hw_class_index);
    if (hw_class == NULL)
	return NULL;

    str = format(NULL, "  %s interface: %s\n", is_rx ? "Receive" : "Transmit",
		 hi->name);

    if (addr)
	/* print the configured source/dest address instead of the interface
	* address.
	*/
	str = format(str, "  %s address: %U\n",
		     is_rx ? "Source" : "Destination",
		     hw_class->format_address, addr);

    vec_add1(str, 0);
    return str;
}
#endif /* ETFS_PORTS_PHYSICAL_ONLY */

static u8 *
format_etfs3_sw_itf(
    u32 idx,
    _Bool is_rx,
    const u8 * const addr)
{
    vnet_main_t *vnm = vnet_get_main ();
    u8 *str;

    str = format(NULL, "  %s interface: %U\n",
	is_rx ? "Receive" : "Transmit",
	format_vnet_sw_if_index_name, vnm, idx);

    if (addr) {
	vnet_hw_interface_t *hi;
	vnet_hw_interface_class_t *hw_class;

	/*
	 * print the configured source/dest address instead of the interface
	 * address.
	 */

	hi = vnet_get_sup_hw_interface (vnm, idx);
	if (!hi)
	    goto done;

	hw_class = vnet_get_hw_interface_class (vnm, hi->hw_class_index);
	if (!hw_class)
	    goto done;

	str = format(str, "  %s address: %U\n",
		     is_rx ? "Source" : "Destination",
		     hw_class->format_address, addr);
    }

done:
    vec_add1(str, 0);
    return str;
}

static void
format_etfs3_encap_flow(
    BVT(clib_bihash_kv) * hash,
    void *_arg)
{
    struct format_etfs_callback_arg *arg = _arg;
    u8 *rx_hw_info = NULL;
    u8 *tx_hw_info = NULL;
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_hw_interface_t *tx_hw_if;
    vnet_main_t *vnm = vnet_get_main ();
#endif
    const state_encap_flow_v2_t * const f =
	(const state_encap_flow_v2_t * const)hash->value;

    if (!(arg->index == (u16)~0 || arg->index == f->config.index))
	return;

#if ETFS_PORTS_PHYSICAL_ONLY
    rx_hw_info = format_etfs3_hw_itf(f->config.if_hw_index_rx, true,
				 f->config.ether_header + 6);
#else
    rx_hw_info = format_etfs3_sw_itf(f->config.if_index_rx, true,
				 f->config.ether_header + 6);
#endif
    if (rx_hw_info == NULL)
	rx_hw_info = format(NULL, "(unknown)\0");

#if ETFS_PORTS_PHYSICAL_ONLY
    tx_hw_if = vnet_get_sup_hw_interface(vnm, f->config.if_index_tx);
    if (tx_hw_if == NULL)
	goto out;

    tx_hw_info = format_etfs3_hw_itf(tx_hw_if->hw_if_index, false,
				 f->config.ether_header + 0);
#else
    tx_hw_info = format_etfs3_sw_itf(f->config.if_index_tx, false,
				 f->config.ether_header + 0);
#endif
    if (tx_hw_info == NULL)
	tx_hw_info = format(NULL, "(unknown)\0");

    if (rx_hw_info == NULL || tx_hw_info == NULL) {
	etfs3_log(VLIB_LOG_LEVEL_WARNING,
		  "Unable to allocate memory for interface string");
	goto out;
    }

    *arg->str = format(*arg->str, "Encap flow %u\n", f->config.index);
    *arg->str = format(*arg->str, "%s%s", (char *)rx_hw_info, (char *)tx_hw_info);
    *arg->str = format(*arg->str, "  ETFS frame size: %u\n",
		       f->config.framesize);
    *arg->str = format(*arg->str,
		       "  rate: %u bps\n  max aggregation time: %u usec\n\n",
		       f->config.tx_rate_bits_msec*1000,
		       f->config.max_aggr_time_usec);

out:
    if (rx_hw_info)
	vec_free(rx_hw_info);
    if (tx_hw_info)
	vec_free(tx_hw_info);
}

static void
format_etfs3_decap_flow(
    BVT(clib_bihash_kv) * hash,
    struct format_etfs_callback_arg *arg)
{
    u8 *rx_hw_info = NULL;
    u8 *tx_hw_info = NULL;
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_hw_interface_t *hw_if;
    vnet_main_t *vnm = vnet_get_main ();
#endif
    const state_decap_flow_v2_t * const f =
	(const state_decap_flow_v2_t * const)hash->value;

    if (!(arg->index == (u16)~0 || arg->index == f->config.index))
	return;

#if ETFS_PORTS_PHYSICAL_ONLY
    hw_if = vnet_get_sup_hw_interface(vnm, f->config.if_index_rx);
    if (hw_if == NULL)
	return;

    rx_hw_info = format_etfs3_hw_itf(hw_if->hw_if_index, true, NULL);
#else
    rx_hw_info = format_etfs3_sw_itf(f->config.if_index_rx, true, NULL);
#endif
    if (rx_hw_info == NULL)
	rx_hw_info = format(NULL, "(unknown)\0");

#if ETFS_PORTS_PHYSICAL_ONLY
    hw_if = vnet_get_sup_hw_interface(vnm, f->config.if_index_tx);
    if (hw_if == NULL)
	goto out;

    tx_hw_info = format_etfs3_hw_itf(hw_if->hw_if_index, false, NULL);
#else
    tx_hw_info = format_etfs3_sw_itf(f->config.if_index_tx, false, NULL);
#endif
    if (tx_hw_info == NULL)
	tx_hw_info = format(NULL, "(unknown)\0");

    if (rx_hw_info == NULL || tx_hw_info == NULL) {
	etfs3_log(VLIB_LOG_LEVEL_WARNING,
		  "Unable to allocate memory for interface string");
	goto out;
    }

    *arg->str = format(
	*arg->str, "Decap flow %u%s\n%s%s\n",
	f->config.index,
	(arg->macsec? ".m\n  MACSEC: enabled": "\n  MACSEC: disabled"),
	(char *)rx_hw_info,
	(char *)tx_hw_info);

out:
    if (rx_hw_info)
	vec_free(rx_hw_info);
    if (tx_hw_info)
	vec_free(tx_hw_info);
}

static void
format_etfs3_common_flow_vec(
    u16 index,
    struct format_etfs_callback_arg *arg)
{
    struct format_etfs_callback_results res;

    res.str = vec_dup(*arg->str);
    vec_add1(res.str, 0);
    res.index = index;
    vec_reset_length(*arg->str);
    vec_add1(arg->resv, res);
}

/* Build a vector of (index, str) pairs to be sorted on index */
static int
format_etfs3_decap_flow_vec(
    BVT(clib_bihash_kv) * hash,
    void *_arg)
{
    struct format_etfs_callback_arg *arg = _arg;
    const state_decap_flow_v2_t * const f =
	(const state_decap_flow_v2_t * const)hash->value;

    format_etfs3_decap_flow(hash, arg);
    if (*arg->str == NULL)
        return (BIHASH_WALK_CONTINUE);

    format_etfs3_common_flow_vec(f->config.index, arg);

    return (BIHASH_WALK_CONTINUE);
}

/* Build a vector of (index, str) pairs to be sorted on index */
static int
format_etfs3_encap_flow_vec(
    BVT(clib_bihash_kv) * hash,
    void *_arg)
{
    struct format_etfs_callback_arg *arg = _arg;
    const state_encap_flow_v2_t * const f =
	(const state_encap_flow_v2_t * const)hash->value;

    format_etfs3_encap_flow(hash, arg);
    if (*arg->str == NULL)
        return (BIHASH_WALK_CONTINUE);

    format_etfs3_common_flow_vec(f->config.index, arg);

    return (BIHASH_WALK_CONTINUE);
}

static int
format_etfs_callback_results_cmp(
    const void * const a,
    const void * const b)
{
    const struct format_etfs_callback_results * const resa = a;
    const struct format_etfs_callback_results * const resb = b;

    return (int)resa->index - (int)resb->index;
}

static clib_error_t *
show_etfs3_flow_fn(
    vlib_main_t		*vm,
    unformat_input_t	*input,
    vlib_cli_command_t	*cmd)
{
    u8 *str = NULL;
    u32 index_filter = ~0;
    unformat_input_t _linput, *linput = &_linput;
    enum filter_e {
	ALL,
	ENCAP_ONLY,
	DECAP_ONLY,
    };
    enum filter_e filter = ALL;
    struct format_etfs_callback_arg arg;
    struct format_etfs_callback_results *res;

    /* "show etfs flow [encap|decap [<flow>]]", */
    if (unformat_user (input, unformat_line_input, linput)) {
	while (unformat_check_input (linput) != UNFORMAT_END_OF_INPUT) {
	    if (filter == ALL) {
		if (unformat (linput, "encap"))
		  filter = ENCAP_ONLY;
		else if (unformat (linput, "decap"))
		  filter = DECAP_ONLY;
		else
		    return clib_error_return (0, "argument must be either 'encap' or 'decap'");
	    } else {
		if (!unformat(linput, "%u", &index_filter) ||
		    index_filter >= 65536)
		  return clib_error_return (0, "index must be a non-negative integer < 65536");
	    }
	}
	unformat_free(linput);
    }

    memset(&arg, 0, sizeof(arg));
    arg.index = (u16)(index_filter & 0xffff);
    arg.str = &str;
    arg.resv = NULL;

    if (filter == ALL || filter == ENCAP_ONLY) {
	BV(clib_bihash_foreach_key_value_pair)(&etfs3_main.encap_flow_table,
					       format_etfs3_encap_flow_vec,
					       &arg);
	vec_sort_with_function(arg.resv, format_etfs_callback_results_cmp);
	vec_foreach(res, arg.resv) {
	    vlib_cli_output(vm, (char *)res->str);
	    vec_free(res->str);
	}
	vec_reset_length(arg.resv);
    }

    if (filter == ALL || filter == DECAP_ONLY) {
	/* Non-macsec flows */
	arg.macsec = 0;
	BV(clib_bihash_foreach_key_value_pair)(&etfs3_main.decap_flow_table,
					       format_etfs3_decap_flow_vec,
					       &arg);
	vec_sort_with_function(arg.resv, format_etfs_callback_results_cmp);
	vec_foreach(res, arg.resv) {
	    vlib_cli_output(vm, (char *)res->str);
	    vec_free(res->str);
	}
	vec_reset_length(arg.resv);

	/* macsec flows */
	arg.macsec = 1;
	BV(clib_bihash_foreach_key_value_pair)(
	    &etfs3_main.decap_flow_table_macsec,
	    format_etfs3_decap_flow_vec,
	    &arg);
	vec_sort_with_function(arg.resv, format_etfs_callback_results_cmp);
	vec_foreach(res, arg.resv) {
	    vlib_cli_output(vm, (char *)res->str);
	    vec_free(res->str);
	}
    }

    vec_free(arg.resv);
    vec_free(str);
    return 0;
}

VLIB_CLI_COMMAND (show_etfs3_flow, static) = {
    .path = "show etfs3 flow",
    .short_help =
    "show etfs flow [encap|decap [<flow>]]",
    .function = show_etfs3_flow_fn,
};

static clib_error_t *
clear_etfs3_counters_fn(
    vlib_main_t		*vm,
    unformat_input_t	*_input,
    vlib_cli_command_t	*cmd)
{
    etfs_clear_counters();
    return 0;
}

VLIB_CLI_COMMAND (clear_etfs3_counters, static) = {
    .path = "clear etfs3 counters",
    .short_help =
    "clear etfs3 counters",
    .function = clear_etfs3_counters_fn,
};

static u8 *
format_etfs3_debug_decap_flow(u8 * s, va_list * args)
{
    state_decap_flow_v2_t		*df;
    counter_t				sstats;
    vlib_counter_t			cstats;

    df = va_arg (*args, state_decap_flow_v2_t *);

    s = format(s,
	    "Decap on rx interface index %d, %smacsec\n",
	    df->config.if_index_rx,
	    (df->config.macsec_enabled? "": "NON-"));

#define _(E,n)								\
    vlib_get_combined_counter(&etfs3_main.decap_ccm[ETFS_DECAP_CCTR_##E],\
	df->config.index, &cstats);					\
    s = format(s, "  decap %s pkts: %lu, bytes: %lu\n",			\
	n, cstats.packets, cstats.bytes);

    foreach_etfs_decap_combined_counter
#undef _

#define _(E,n)						\
    sstats = vlib_get_simple_counter(			\
	&etfs3_main.decap_scm[ETFS_DECAP_SCTR_##E],	\
	df->config.index);				\
    s = format(s, "  decap %s %lu\n", n, sstats);

    foreach_etfs_decap_simple_counter
#undef _

    s = format(s, "\n");

    return s;
}

static u8 *
format_etfs3_debug_encap_flow(u8 * s, va_list * args)
{
    state_encap_flow_v2_t		*ef;

    counter_t				sstats;
    vlib_counter_t			cstats;

    ef = va_arg (*args, state_encap_flow_v2_t *);

    s = format(s,
	    "Decap on rx interface index %d, %smacsec\n",
	    ef->config.if_index_rx,
	    (ef->config.macsec_enabled? "": "NON-"));

#define _(E,n)								\
    vlib_get_combined_counter(&etfs3_main.encap_ccm[ETFS_ENCAP_CCTR_##E],\
	ef->config.index, &cstats);					\
    s = format(s, "  encap %s pkts: %lu, bytes: %lu\n",			\
	n, cstats.packets, cstats.bytes);

    foreach_etfs_encap_combined_counter
#undef _

#define _(E,n)						\
    sstats = vlib_get_simple_counter(			\
	&etfs3_main.encap_scm[ETFS_ENCAP_SCTR_##E],	\
	ef->config.index);				\
    s = format(s, "  encap %s %lu\n", n, sstats);

    foreach_etfs_encap_simple_counter
#undef _

    s = format(s, "  inprogress UF bytes: %u\n", ef->encap.uf_bytes);
    if (ef->encap.bi_inprogress != ~0u)
	s = format(s, "  inprogress BI: %u\n", ef->encap.bi_inprogress);
    else
	s = format(s, "  inprogress BI: -\n");

    s = format(s, "  %U", etfs_output_byte_counter_q_format, ef);

    s = format(s, "\n");

    return s;
}

/**
 * @brief debug
 *
 */
static clib_error_t *
debug_command_fn(
    vlib_main_t		*vm,
    unformat_input_t	*_input,
    vlib_cli_command_t	*cmd)
{
#if ETFS_PORTS_PHYSICAL_ONLY
    vnet_sw_interface_t		*sw;
#endif

    int	encap_debug	= 0;
    u32 rxport		= ~0;
    int	decap_debug	= 0;
    u32	start		= 0;
    u32 buffer_note_count = 0;

    /* Get a line of input. */
    unformat_input_t _line_input, *input = &_line_input;
    if (!unformat_user (_input, unformat_line_input, input))
	return 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat(input, "encap rx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &rxport)) {

	    encap_debug = 1;

	} else if (unformat(input, "decap rx %U", unformat_vnet_sw_interface,
	    etfs3_main.vnet_main, &rxport)) {

	    decap_debug = 1;

	} else if (unformat(input, "n %u", &buffer_note_count)) {
	    vlib_buffer_note_dump_bulk(buffer_note_count);
	    return 0;
	} else if (unformat(input, "b %u", &start)) {
	} else {
	    break;
	}
    }
    unformat_free(input);

    if (!encap_debug && !decap_debug) {
	return clib_error_return (0, "err, unknown command");
    }

    if (rxport == ~0)
	return clib_error_return (0, "Please specify a receive interface");

    if (pool_is_free_index(etfs3_main.vnet_main->interface_main.sw_interfaces,
	rxport)) {
	    return clib_error_return (0,
		"Invalid rx interface, only works on physical ports");
    }

#if ETFS_PORTS_PHYSICAL_ONLY
    /* Not a physical port? */
    sw = vnet_get_sw_interface (etfs3_main.vnet_main, rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return clib_error_return (0,
	    "Invalid rx interface, only works on physical ports");
#endif

    if (encap_debug) {
	state_encap_flow_v2_t	*ef;
	u8			*s = NULL;

	if ((ef = encap_flow_get(rxport))) {
	    s = format(s, "%U\n", format_etfs3_debug_encap_flow, ef);
	} else {
	    s = format(s, "no encap flow matching rx port %u", rxport);
	}

	vlib_cli_output (vm, "%v", s);
	vec_free (s);
    }

    if (decap_debug) {

	state_decap_flow_v2_t	*df;
	u8			*s = NULL;

	if ((df = decap_flow_get(rxport, true))) {
	    s = format(s, "%U\n", format_etfs3_debug_decap_flow, df);
	}
	if ((df = decap_flow_get(rxport, false))) {
	    s = format(s, "%U\n", format_etfs3_debug_decap_flow, df);
	}
	if (!s) {
	    s = format(s, "no decap flow matching rx port %u", rxport);
	}

	vlib_cli_output (vm, "%v", s);
	vec_free (s);
    }

    return 0;
}

/**
 * @brief CLI command to enable/disable the etfs3 decap plugin.
 */
VLIB_CLI_COMMAND (debug_command, static) = {
    .path = "etfs3 debug",
    .short_help =
    "etfs3 debug encap|decap rx <ifname>",
    .function = debug_command_fn,
};

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
etfs3_plugin_api_hookup (vlib_main_t *vm)
{
  etfs3_main_t * sm = &etfs3_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
    foreach_etfs3_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <etfs3/etfs3_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (etfs3_main_t * sm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_etfs3;
#undef _
}


etfs3_main_t	etfs3_main;


/*
 * Even though we get invoked via macsec, we have to examine ipsec
 * to determine the identity of the new encrypt node.
 */
static clib_error_t *
etfs3_crypto_backend_update(vlib_main_t * vm)
{
    macsec_main_t	*mm = &macsec_main;

    etfs3_main.macsec_encrypt_node_index = mm->macsec_encrypt_node_index;

    /* idempotent */
    etfs3_main.macsec_encrypt_next_node_index = 
	    vlib_node_add_next(vm, etfs_output_node.index,
		mm->macsec_encrypt_node_index);

    ETFS_DEBUG_F(CONTROL, 1, "macsec_encrypt_node_index: %u (\"%s\")\n",
	etfs3_main.macsec_encrypt_node_index,
	vlib_get_node(vm, etfs3_main.macsec_encrypt_node_index)->name);

    return NULL;
}

static clib_error_t *
etfs3_init(
    vlib_main_t		*vm)
{
    u8			*name;
    clib_error_t	*error = NULL;
    vlib_thread_main_t	*tm = vlib_get_thread_main();
    macsec_main_t	*mm = &macsec_main;
    u32			thread_idx;

    etfs3_main.vlib_main = vm;
    etfs3_main.vnet_main = vnet_get_main();

    etfs3_main.macsec_encrypt_node_index = ~0;

    /*
     * API setup
     */
    name = format (0, "etfs3_%08x%c", api_version, 0); /* see etfs3.c */

    /* Ask for a correctly-sized block of API message decode slots */
    etfs3_main.msg_id_base = vl_msg_api_get_msg_ids(
	(char *) name, VL_MSG_FIRST_AVAILABLE);

    if ((error = etfs3_plugin_api_hookup (vm))) {
	vec_free(name);
	return error;
    }

    /* Add our API messages to the global name_crc hash table */
    setup_message_id_table (&etfs3_main, vlibapi_get_main());

    vec_free(name);

    mm->etfs3_backend_update_cb = etfs3_crypto_backend_update;

    /*
     * Create per-interface flow configuration hash tables
     *
     * These tables are 8-byte key, 8-byte value.
     * Key is interface number, value is pointer to dynamically-allocated
     * encap/decap flow structure.
     */
    BV (clib_bihash_init) (&etfs3_main.encap_flow_table,
	"encap flow table", ENCAP_FLOW_TBL_NUM_BUCKETS,
	ENCAP_FLOW_TBL_MEMORY_SIZE);

    BV (clib_bihash_init) (&etfs3_main.decap_flow_table,
	"decap flow table", ENCAP_FLOW_TBL_NUM_BUCKETS,
	ENCAP_FLOW_TBL_MEMORY_SIZE);

    BV (clib_bihash_init) (&etfs3_main.decap_flow_table_macsec,
	"decap flow table", ENCAP_FLOW_TBL_NUM_BUCKETS,
	ENCAP_FLOW_TBL_MEMORY_SIZE);

    clib_spinlock_init(&etfs3_main.encap_flow_table_lock);

    vec_validate_init_empty(etfs3_main.workers_main, tm->n_vlib_mains,
	(etfs_thread_main_t){0});
    vec_foreach_index (thread_idx, etfs3_main.workers_main) {
	etfs_thread_main_t	*tm;

	tm = vec_elt_at_index(etfs3_main.workers_main, thread_idx);
	tm->thread_index = thread_idx;
    }

    /*
     * register decap-rx node to receive packets of matching etype
     */
    vlib_node_t	*node_decap_rx = vlib_get_node_by_name(vm,
	(u8*)"etfs-decap-rx");
    if (node_decap_rx) {
	ethernet_register_input_type(vm, ETFS_ETHERTYPE_TX,
	    node_decap_rx->index);
    } else {
	error = clib_error_return(0, "ethernet_register_input_type failed");
	return error;
    }

    etfs3_main.log_class = vlib_log_register_class ("etfs3", 0);

    /*
     * Counters
     */

    clib_spinlock_init (&etfs3_main.counter_lock);
    clib_spinlock_lock (&etfs3_main.counter_lock);

#define _(E, n)								\
    etfs3_main.global_scm[ETFS_GLOBAL_SCTR_##E].name = n;		\
    etfs3_main.global_scm[ETFS_GLOBAL_SCTR_##E].stat_segment_name =	\
	"/etfs3/global/" n;
    foreach_etfs_global_simple_counter
#undef _

    /*
     * global counters have only one possible index value (0), so
     * we only need to extend their vectors once at init time.
     */
    for (uint i = 0; i < ETFS_GLOBAL_SCTR_N_COUNTERS; ++i) {
	vlib_validate_simple_counter(&etfs3_main.global_scm[i], 0);
	vlib_zero_simple_counter(&etfs3_main.global_scm[i], 0);
    }

#define _(E, n)								\
    etfs3_main.encap_scm[ETFS_ENCAP_SCTR_##E].name = n;			\
    etfs3_main.encap_scm[ETFS_ENCAP_SCTR_##E].stat_segment_name =	\
	"/etfs3/encap/" n;
    foreach_etfs_encap_simple_counter
#undef _

#define _(E, n)								\
    etfs3_main.decap_scm[ETFS_DECAP_SCTR_##E].name = n;			\
    etfs3_main.decap_scm[ETFS_DECAP_SCTR_##E].stat_segment_name =	\
	"/etfs3/decap/" n;
    foreach_etfs_decap_simple_counter
#undef _

#define _(E, n)								\
    etfs3_main.encap_ccm[ETFS_ENCAP_CCTR_##E].name = n;			\
    etfs3_main.encap_ccm[ETFS_ENCAP_CCTR_##E].stat_segment_name =	\
	"/etfs3/encap/" n;
    foreach_etfs_encap_combined_counter
#undef _

#define _(E, n)								\
    etfs3_main.decap_ccm[ETFS_DECAP_CCTR_##E].name = n;			\
    etfs3_main.decap_ccm[ETFS_DECAP_CCTR_##E].stat_segment_name =	\
	"/etfs3/decap/" n;
    foreach_etfs_decap_combined_counter
#undef _

    clib_spinlock_unlock (&etfs3_main.counter_lock);


    etfs3_crypto_backend_update(vm);

    return error;
}

VLIB_INIT_FUNCTION (etfs3_init);


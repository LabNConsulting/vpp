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
/*
 *------------------------------------------------------------------
 * etfs3_test.c - test harness plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <etfs3/etfs3.h>

#define __plugin_msg_base etfs3_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <etfs3/etfs3_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <etfs3/etfs3_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <etfs3/etfs3_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <etfs3/etfs3_all_api_h.h> 
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <etfs3/etfs3_all_api_h.h>
#undef vl_api_version


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} etfs3_test_main_t;

etfs3_test_main_t etfs3_test_main;

#define foreach_standard_reply_retval_handler		\
_(etfs3_encap_add_reply)				\
_(etfs3_decap_add_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = etfs3_test_main.vat_main;    \
        i32 retval = clib_net_to_host_u32(mp->retval);  \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(ETFS3_ENCAP_ADD_REPLY, etfs3_encap_add_reply)				\
_(ETFS3_ENCAP_ADD_REPLY, etfs3_decap_add_reply)


static int
api_etfs3_encap_add (vat_main_t * vam)
{
    unformat_input_t	*i = vam->input;
    int			ret;
    vnet_main_t		*vnm = vnet_get_main();

    vl_api_etfs3_encap_add_t	mps;
    vl_api_etfs3_encap_add_t	*mp;

    int			set_stea = 0;
    int			set_dtea = 0;

    mps.framesize		= ETFS_MTDU_FRAME_SIZE_DEFAULT;
    mps.tx_rate_bits_msec	= ETFS_TX_RATE_BITSPERMSEC_DEFAULT;
    mps.max_aggr_time_usec	= ETFS_MAX_AGGR_TIME_USEC_DEFAULT;
    mps.rxport			= (u16)~0;
    mps.txport			= (u16)~0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat(i, "rx %U", unformat_sw_if_index, &mps.rxport))
	    ;
	else if (unformat(i, "tx %U", unformat_sw_if_index, &mps.txport))
	    ;
	else if (unformat(i, "fs %u", &mps.framesize))
	    ;
	else if (unformat(i, "rate %u", &mps.tx_rate_bits_msec))
	    ;
	else if (unformat(i, "maxagg %u", &mps.max_aggr_time_usec))
	    ;
	else if (unformat(i, "stea %U", unformat_ethernet_address, mps.stea))
	    set_stea = 1;
	else if (unformat(i, "dtea %U", unformat_ethernet_address, mps.dtea))
	    set_dtea = 1;
	else
	    break;
    }

    if (mps.rxport == (u16)~0) {
	errmsg ("missing receive interface");
        return -99;
    }
    if (mps.txport == (u16)~0) {
	errmsg ("missing transmit interface");
        return -99;
    }
    if (!set_stea) {
	errmsg ("missing src tx ethernet addr");
        return -99;
    }
    if (!set_dtea) {
	errmsg ("missing dst tx ethernet addr");
        return -99;
    }

    /* Utterly wrong? */
    if (pool_is_free_index(vnm->interface_main.sw_interfaces, mps.rxport)) {
	    errmsg("Invalid rx interface, only works on physical ports");
	    return -99;
    }
    if (pool_is_free_index(vnm->interface_main.sw_interfaces, mps.txport)) {
	    errmsg("Invalid tx interface, only works on physical ports");
	    return -99;
    }

    /* Not a physical port? */
    vnet_sw_interface_t	*sw;
    sw = vnet_get_sw_interface (vnm, mps.rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE) {
	errmsg("Invalid rx interface, only works on physical ports");
	return -99;
    }

    sw = vnet_get_sw_interface (vnm, mps.txport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE) {
	errmsg("Invalid tx interface, only works on physical ports");
	return -99;
    }

    /* Construct the API message */
    M(ETFS3_ENCAP_ADD, mp);

    *mp = mps;

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W (ret);
    return ret;
}


static int
api_etfs3_decap_add (vat_main_t * vam)
{
    unformat_input_t	*i = vam->input;
    int			ret;
    vnet_main_t		*vnm = vnet_get_main();

    vl_api_etfs3_decap_add_t	mps;
    vl_api_etfs3_decap_add_t	*mp;

    mps.rxport			= (u16)~0;
    mps.txport			= (u16)~0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat(i, "rx %U", unformat_sw_if_index, &mps.rxport))
	    ;
	else if (unformat(i, "tx %U", unformat_sw_if_index, &mps.txport))
	    ;
	else
	    break;
    }

    if (mps.rxport == (u16)~0) {
	errmsg ("missing receive interface");
        return -99;
    }
    if (mps.txport == (u16)~0) {
	errmsg ("missing transmit interface");
        return -99;
    }

    /* Utterly wrong? */
    if (pool_is_free_index(vnm->interface_main.sw_interfaces, mps.rxport)) {
	    errmsg("Invalid rx interface, only works on physical ports");
	    return -99;
    }
    if (pool_is_free_index(vnm->interface_main.sw_interfaces, mps.txport)) {
	    errmsg("Invalid tx interface, only works on physical ports");
	    return -99;
    }

    /* Not a physical port? */
    vnet_sw_interface_t	*sw;
    sw = vnet_get_sw_interface (vnm, mps.rxport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE) {
	errmsg("Invalid rx interface, only works on physical ports");
	return -99;
    }

    sw = vnet_get_sw_interface (vnm, mps.txport);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE) {
	errmsg("Invalid tx interface, only works on physical ports");
	return -99;
    }

    /* Construct the API message */
    M(ETFS3_ENCAP_ADD, mp);

    *mp = mps;

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W (ret);
    return ret;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(etfs3_encap_add, "rx <intfc> tx <intfc> [fs <len>] [rate <bits/msec>] [maxagg <usec>] stea <ethaddr> dtea <ethaddr>")	\
_(etfs3_decap_add, "rx <intfc> tx <intfc>")

static void etfs3_api_hookup (vat_main_t *vam)
{
    etfs3_test_main_t * sm = &etfs3_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
    foreach_vpe_api_msg;
#undef _    
    
    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  etfs3_test_main_t * sm = &etfs3_test_main;
  u8 * name;

  sm->vat_main = vam;

  name = format (0, "etfs3_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    etfs3_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}

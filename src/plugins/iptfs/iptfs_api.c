/*
 * January 10 2020, Christian E. Hopps <chopps@labn.net>
 *
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
#include <vlib/unix/unix.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <iptfs/ipsec_iptfs.h>

/* Declare message IDs */
#include <iptfs/iptfs_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <iptfs/iptfs_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <iptfs/iptfs_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <iptfs/iptfs_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <iptfs/iptfs_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE ipsec_iptfs_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#define foreach_iptfs_plugin_api_msg \
  _ (IPTFS_CLEAR_COUNTERS, iptfs_clear_counters)

static void
vl_api_iptfs_clear_counters_t_handler (vl_api_iptfs_clear_counters_t *mp)
{
  vl_api_iptfs_clear_counters_reply_t *rmp;
  int rv = 0;
  iptfs_clear_counters ();
  REPLY_MACRO (VL_API_IPTFS_CLEAR_COUNTERS_REPLY +
	       ipsec_iptfs_main.msg_id_base);
}

#define vl_msg_name_crc_list
#include <iptfs/iptfs_all_api_h.h>
#undef vl_msg_name_crc_list

clib_error_t *
iptfs_api_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();
  u8 *name = format (0, "etfs3_%08x%c", api_version, 0); /* see etfs3.c */

  /* Ask for a correctly-sized block of API message decode slots */
  ipsec_iptfs_main.msg_id_base =
      vl_msg_api_get_msg_ids ((char *)name, VL_MSG_FIRST_AVAILABLE);

#define _(N, n)                                                             \
  vl_msg_api_set_handlers ((VL_API_##N + ipsec_iptfs_main.msg_id_base), #n, \
			   vl_api_##n##_t_handler, vl_noop_handler,         \
			   vl_api_##n##_t_endian, vl_api_##n##_t_print,     \
			   sizeof (vl_api_##n##_t), 1);
  foreach_iptfs_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
#define _(id, n, crc)                           \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, \
			       id + ipsec_iptfs_main.msg_id_base);
  foreach_vl_msg_name_crc_iptfs;
#undef _

  return 0;
}

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

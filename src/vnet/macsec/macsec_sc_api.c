/*
 * Copyright (c) 2021, LabN Consulting, L.L.C.
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

#include <vnet/macsec/macsec.h>
#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/vnet_msg_enum.h>

#define vl_typedefs
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg					\
_(MACSEC_SC_DUMP, macsec_sc_dump)

typedef struct _sa_details_args_t {
  BVT (clib_bihash_kv)	*exemplar;
  vl_api_registration_t	*reg;
  u32 context;
  int is_generation;
} sa_details_args;

static void
send_macsec_sc_details_one(
    BVT (clib_bihash_kv)	*pKvTest,
    sa_details_args		*sdargs)
{
    vl_api_macsec_sc_details_t	*mp;

    mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_MACSEC_SC_DETAILS);
    mp->context = sdargs->context;
    mp->ipsec_sa_index = htonl(pKvTest->value);
    mp->is_generation = sdargs->is_generation;
    memcpy(mp->sci, &pKvTest->key, sizeof(mp->sci));

    vl_api_send_msg (sdargs->reg, (u8 *) mp);
}

static int
send_macsec_sc_details(
    BVT (clib_bihash_kv)	*pKvTest,
    void			*arg)
{
    sa_details_args *sdargs = arg;

    if (sdargs->exemplar->value == (u32)~0 ||
        sdargs->exemplar->value == pKvTest->value)
      {
        send_macsec_sc_details_one(pKvTest, sdargs);
        if (sdargs->exemplar->value == pKvTest->value)
            return BIHASH_WALK_STOP;
      }
    return BIHASH_WALK_CONTINUE;
}

static void
vl_api_macsec_sc_dump_t_handler (vl_api_macsec_sc_dump_t * mp)
{
  vl_api_registration_t *reg;
  macsec_main_t *mm = &macsec_main;
  BVT (clib_bihash_kv)	kv;
  sa_details_args sdargs;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  kv.key = ~0;
  kv.value = (uintptr_t)ntohl(mp->ipsec_sa_index);

  sdargs.exemplar = &kv;
  sdargs.reg = reg;
  sdargs.context = mp->context;

  if (mp->dump_verification)
    {
      sdargs.is_generation = 0;
      clib_spinlock_lock(&macsec_main.decrypt_sa_table_lock);
      BV(clib_bihash_foreach_key_value_pair)(&mm->decrypt_sa_table,
         send_macsec_sc_details, &sdargs);
      clib_spinlock_unlock(&macsec_main.decrypt_sa_table_lock);
    }
  if (mp->dump_generation)
    {
      sdargs.is_generation = 1;
      clib_spinlock_lock(&macsec_main.encrypt_sa_table_lock);
      BV(clib_bihash_foreach_key_value_pair)(&mm->encrypt_sa_table,
         send_macsec_sc_details, &sdargs);
      clib_spinlock_unlock(&macsec_main.encrypt_sa_table_lock);
    }
}


#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_macsec_sc;
#undef _
}

static clib_error_t *
macsec_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (macsec_api_hookup);

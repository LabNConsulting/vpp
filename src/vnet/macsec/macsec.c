/*
 * Copyright (c) 2020, LabN Consulting, L.L.C.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlib/vlib.h>
#include <vnet/ipsec/ipsec.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/macsec/macsec.h>	/* incl last to avoid overriding bihash size */


macsec_main_t	macsec_main;

#define MACSEC_DECRYPT_NODE_NAME	"dpdk-macsec-decrypt"

#ifdef MACSEC_COUNTERS_ENABLE
void
macsec_validate_counters (u32 if_index, u32 sa_index)
{
  clib_warning("%s(%u, %u)", __func__, if_index, sa_index);

# define _(sym, typ, field, name, statsegname) \
  vlib_validate_##typ##_counter(&macsec_main.counters.field , if_index); \
  vlib_zero_##typ##_counter(&macsec_main.counters.field , if_index);

  foreach_macsec_counter
# undef _

# define _(sym, typ, field, name, statsegname) \
  vlib_validate_##typ##_counter(&macsec_main.counters.field , sa_index); \
  vlib_zero_##typ##_counter(&macsec_main.counters.field , sa_index);

  foreach_macsec_sa_counter
# undef _
}

static void
macsec_init_counters (void) {
# define _(sum, typ, field, statname, statsegname) \
  macsec_main.counters.field.name = #statname; \
  macsec_main.counters.field.stat_segment_name = #statsegname "/" #statname;

    foreach_macsec_all_counters
# undef _
    macsec_validate_counters (0, 0);
}
#endif


/*
 * ipsec calls this function when its backend changes, which implies a
 * backend change for macsec.
 */
void
macsec_backend_update(vlib_main_t *vm)
{
    ipsec_main_t	*im = &ipsec_main;
    macsec_main_t	*mm = &macsec_main;

    /*
     * route received macsec packets to the correct node
     */

    if (im->macsec_decrypt_node_index != (u32)~0) {
	ethernet_register_input_type(vm, MACSEC_ETYPE, im->macsec_decrypt_node_index);
	macsec_main.crypto_backend_present = 1;
    } else {
	ethernet_register_input_type(vm, MACSEC_ETYPE, ~0);
	macsec_main.crypto_backend_present = 0;
    }

    /*
     * save the identity of the new encryption node: etfs will
     * copy from us.
     */
    mm->macsec_encrypt_node_index = im->macsec_encrypt_node_index;

    /*
     * Signal etfs that backend changed
     */
    if (mm->etfs3_backend_update_cb)
	(*mm->etfs3_backend_update_cb) (vm);

}

static clib_error_t *
macsec_init(vlib_main_t *vm)
{
    clib_error_t	*error = NULL;

    /*
     * initialize flow tables to map SCI values to SAs
     */
    BV (clib_bihash_init) (&macsec_main.decrypt_sa_table,
	"decrypt SA table", MACSEC_FLOW_TBL_NUM_BUCKETS,
	MACSEC_FLOW_TBL_MEMORY_SIZE);
    BV (clib_bihash_init) (&macsec_main.encrypt_sa_table,
	"encrypt SA table", MACSEC_FLOW_TBL_NUM_BUCKETS,
	MACSEC_FLOW_TBL_MEMORY_SIZE);
    clib_spinlock_init(&macsec_main.decrypt_sa_table_lock);
    clib_spinlock_init(&macsec_main.encrypt_sa_table_lock);

    vec_validate_aligned(macsec_main.ptd, vlib_num_workers (), CLIB_CACHE_LINE_BYTES);

    /*
     * register post nodes (for vpp native macsec)
     */
    macsec_main.encrypt_async_post_next =
	vnet_crypto_register_post_node( vm, "macsec-encrypt-post");
    macsec_main.decrypt_async_post_next =
	vnet_crypto_register_post_node( vm, "macsec-decrypt-post");

#if 0 /* superseded by macsec_backend_update() */
    /*
     * register decrypt node to receive packets of matching etype
     */
    vlib_node_t *node_decrypt_rx = vlib_get_node_by_name(vm,
	(u8*)MACSEC_DECRYPT_NODE_NAME);
    if (node_decrypt_rx) {
	ethernet_register_input_type(vm, MACSEC_ETYPE, node_decrypt_rx->index);
	macsec_main.crypto_backend_present = 1;
    } else {
	macsec_main.crypto_backend_present = 0;
	clib_warning("%s: no node \"%s\", no MACSEC receive",
	    __func__, MACSEC_DECRYPT_NODE_NAME);
	return error;
    }
#endif

    macsec_main.macsec_encrypt_fq_index =
	vlib_frame_queue_main_init(macsec_encrypt_node.index, 0);
    macsec_main.macsec_decrypt_fq_index =
	vlib_frame_queue_main_init(macsec_decrypt_node.index, 0);

#ifdef MACSEC_COUNTERS_ENABLE
    macsec_init_counters();
#endif

    return error;
}

VLIB_INIT_FUNCTION (macsec_init);

int
macsec_enabled(void)
{
    if (macsec_main.crypto_backend_present)
	return 1;
    return 0;
}

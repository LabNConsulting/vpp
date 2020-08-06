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
#include <vnet/macsec/macsec.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>


macsec_main_t	macsec_main;

#define MACSEC_DECRYPT_NODE_NAME	"dpdk-macsec-decrypt"

static clib_error_t *
macsec_init(vlib_main_t *vm)
{
    clib_error_t	*error = NULL;

    /*
     * initialize receive flow table to map received SCI values
     * to SAs
     */
    BV (clib_bihash_init) (&macsec_main.decrypt_sa_table,
	"decrypt SA table", DECRYPT_FLOW_TBL_NUM_BUCKETS,
	DECRYPT_FLOW_TBL_MEMORY_SIZE);
    clib_spinlock_init(&macsec_main.decrypt_sa_table_lock);

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

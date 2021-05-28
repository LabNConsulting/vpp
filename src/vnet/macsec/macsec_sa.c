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

#include <stddef.h>
#include <vppinfra/types.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/macsec/macsec.h>

#include <vnet/macsec/macsec_sa.h>
#include <vnet/crypto/crypto.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/macsec/macsec_format.h>
#include <vppinfra/bihash_8_8.h>

void
macsec_mk_key (macsec_key_t * key, const u8 * data, u8 len)
{
  memset (key, 0, sizeof (*key));

  if (len > sizeof (key->data))
    key->len = sizeof (key->data);
  else
    key->len = len;

  memcpy (key->data, data, key->len);
}

/*
 * return index of SA that etfs encap will use in datapath when
 * it sends packets to macsec for this SA
 */
int
macsec_sa_add(u32 id, macsec_sa_t *sa, u32 *out_sa_index)
{
    ipsec_key_t ipsec_key;
    int		rc;
    u32		ipsec_sa_index = ~0;

    ASSERT(id == (id & MACSEC_SA_ID_ALLOWED_BITS));

    ipsec_key.len = sa->crypto_key.len;
    ASSERT(sa->crypto_key.len <= IPSEC_KEY_MAX_LEN);
    clib_memcpy(ipsec_key.data, sa->crypto_key.data, sa->crypto_key.len);

    if ((rc =  ipsec_sa_macsec_add(id,
        macsec_map_crypto_alg_to_ipsec(sa->crypto_alg),
        &ipsec_key,
        sa->flags & MACSEC_SA_FLAG_IS_INBOUND,
        sa->flags & MACSEC_SA_FLAG_USE_ANTI_REPLAY,
        sa->replay_window,
        &ipsec_sa_index))) {

	return rc;
    }


    if (out_sa_index)
	*out_sa_index = ipsec_sa_index;

    if (sa->flags & MACSEC_SA_FLAG_IS_INBOUND) {
	BVT (clib_bihash_kv)	kv;

	clib_memcpy(&kv.key, sa->ether_addr, 6);	/* sender's addr */
	* (((u8*)(&kv.key)) + 6) = 0;
	* (((u8*)(&kv.key)) + 7) = 1;			/* SCB not supported */

	kv.value = (uintptr_t)ipsec_sa_index;

#if 0
	u8	*s = 0;

	s = format(s, "key: %U\n", format_hexdump, &kv.key, sizeof(kv.key));
	s = format(s, "key 0x%016lx (size %u), value 0x%lx\n%c",
	    kv.key,
	    sizeof(kv.key),
	    kv.value,
	    0);
	clib_warning("%s", s);
	vec_free(s);
#endif

	clib_spinlock_lock(&macsec_main.decrypt_sa_table_lock);
	int rc;
	rc = BV(clib_bihash_add_del)(&macsec_main.decrypt_sa_table, &kv, 1/*add*/);
	clib_spinlock_unlock(&macsec_main.decrypt_sa_table_lock);
	if (rc) {
	    /* failed to add, so unwind everything */
	    ipsec_sa_macsec_del(ipsec_sa_index);
	    return VNET_API_ERROR_TABLE_TOO_BIG;
	}
    }

    macsec_validate_counters(sa->if_index, ipsec_sa_index);

    return 0;
}

/*
 * Helper function for reverse search in decrypt_sa_table.
 * Only happens when deleting an SA so OK to be inefficient.
 */
static int
set_key_for_sa(
    BVT (clib_bihash_kv)	*pKvTest,
    void			*arg)
{
    BVT (clib_bihash_kv)	*pKvSet = (BVT (clib_bihash_kv) *)arg;

    if (pKvTest->value == pKvSet->value)
      {
        pKvSet->key = pKvTest->key;
        return (BIHASH_WALK_STOP);
      }
    return (BIHASH_WALK_CONTINUE);
}

void
macsec_sa_delete(u32 ipsec_sa_index)
{
    int				rc;
    BVT (clib_bihash_kv)	kv;

    kv.key = ~0;
    kv.value = (uintptr_t)ipsec_sa_index;

    clib_spinlock_lock(&macsec_main.decrypt_sa_table_lock);
    /* reverse lookup */
    BV(clib_bihash_foreach_key_value_pair)(&macsec_main.decrypt_sa_table,
	set_key_for_sa, &kv);
    ASSERT(kv.key != ~0);

    rc = BV(clib_bihash_add_del)(&macsec_main.decrypt_sa_table, &kv, 0/*del*/);
    ASSERT(!rc);
    clib_spinlock_unlock(&macsec_main.decrypt_sa_table_lock);

    ipsec_sa_macsec_del(ipsec_sa_index);
}

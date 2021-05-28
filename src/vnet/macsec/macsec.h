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

#ifndef __MACSEC_H__
#define __MACSEC_H__

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>

#include <vnet/macsec/macsec_sa.h>
#include <vnet/crypto/crypto.h>
#include <vnet/buffer.h>

#define MACSEC_FLOW_TBL_NUM_BUCKETS	32
#define MACSEC_FLOW_TBL_MEMORY_SIZE	(20*1024)
#define MACSEC_COUNTERS_ENABLE 1

typedef struct
{
    u16	next_index;
    u8 error;
} macsec_encrypt_post_data_t;

STATIC_ASSERT (sizeof (macsec_encrypt_post_data_t) <=
    STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
    "Custom meta-data too large for vnet_buffer_opaque_t");

#define macsec_encrypt_post_data(b)				\
    ((macsec_encrypt_post_data_t *)((u8 *)((b)->opaque)		\
    + STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

/*
 * This struct goes in vlib_opaque buffer area
 */
typedef struct
{
    u32	sa_index;
    u8	icv_sz;
    u8	iv_sz;
    u8	is_chain : 1;
    u8	sci_present : 1;	/* debug tracing */
    u8	post_handoff : 1;	/* debug tracing */

    u32	pn;
    i16	current_data;
    i16	current_length;

    u64	kv_key;		/* debug only - can be removed */
} macsec_decrypt_post_data_t;

STATIC_ASSERT (sizeof (macsec_decrypt_post_data_t) <=
    STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
    "Custom meta-data too large for vnet_buffer_opaque_t");

#define macsec_decrypt_post_data(b)				\
    ((macsec_decrypt_post_data_t *)((u8 *)((b)->opaque)		\
    + STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

typedef struct
{
    vlib_buffer_t	*lb;
    u32			free_buffer_index;
    u8			icv_removed;
} macsec_decrypt_post_data2_t;

STATIC_ASSERT (sizeof (macsec_decrypt_post_data2_t) <=
    STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
    "Custom meta-data too large for vnet_buffer_opaque2_t");

#define macsec_decrypt_post_data2(b)					\
    ((macsec_decrypt_post_data2_t *)((u8 *)((b)->opaque2)	\
    + STRUCT_OFFSET_OF (vnet_buffer_opaque2_t, unused)))


typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_t		*crypto_ops;
  vnet_crypto_op_t		*integ_ops;
  vnet_crypto_op_t		*chained_crypto_ops;
  vnet_crypto_op_t		*chained_integ_ops;
  vnet_crypto_op_chunk_t	*chunks;
} macsec_per_thread_data_t;

typedef clib_error_t *(*etfs3_backend_update_cb_t) (vlib_main_t * vm);

/* Counters from IEEE 802.1ae Yang model and SNMP MIB */
#ifdef MACSEC_COUNTERS_ENABLE
# define foreach_macsec_counter \
_(VER_PKTS_UNTAGGED,     simple, ver_in_pkts_untagged,      in-pkts-untagged,     /macsec/verification) \
_(VER_PKTS_NO_TAG,       simple, ver_in_pkts_no_tag,        in-pkts-no-tag,       /macsec/verification) \
_(VER_PKTS_BAD_TAG,      simple, ver_in_pkts_bad_tag,       in-pkts-bad-tag,      /macsec/verification) \
_(VER_PKTS_NO_SA,        simple, ver_in_pkts_no_sa,         in-pkts-no-sa,        /macsec/verification) \
_(VER_PKTS_NO_SA_ERROR,  simple, ver_in_pkts_no_sa_error,   in-pkts-no-sa-error,  /macsec/verification) \
_(VER_PKTS_OVERRUN,      simple, ver_in_pkts_overrun,       in-pkts-overrun,      /macsec/verification) \
_(VER_OCT_VALIDATED,     simple, ver_in_octets_validated,   in-octets-validated,  /macsec/verification) \
_(VER_OCT_DECRYPTED,     simple, ver_in_octets_decrypted,   in-octets-decrypted,  /macsec/verification) \
_(VER_SC_PKTS_OK,        simple, rxsc_in_pkts_ok,           in-pkts-ok,           /macsec/verification/rxsc) \
_(VER_SC_PKTS_UNCHECKED, simple, rxsc_in_pkts_unchecked,    in-pkts-unchecked,    /macsec/verification/rxsc) \
_(VER_SC_PKTS_DELAYED,   simple, rxsc_in_pkts_delayed,      in-pkts-delayed,      /macsec/verification/rxsc) \
_(VER_SC_PKTS_LATE,      simple, rxsc_in_pkts_late,         in-pkts-late,         /macsec/verification/rxsc) \
_(VER_SC_PKTS_INVALID,   simple, rxsc_in_pkts_invalid,      in-pkts-invalid,      /macsec/verification/rxsc) \
_(VER_SC_PKTS_NOT_VALID, simple, rxsc_in_pkts_not_valid,    in-pkts-not-valid,    /macsec/verification/rxsc) \
 \
_(GEN_PKTS_UNTAGGED,     simple, gen_out_pkts_untagged,     out-pkts-untagged,    /macsec/generation) \
_(GEN_PKTS_TOO_LONG,     simple, gen_out_pkts_too_long,     out-pkts-too-long,    /macsec/generation) \
_(GEN_OCT_PROTECTED,     simple, gen_out_octets_protected,  out-octets-protected, /macsec/generation) \
_(GEN_OCT_ENCRYPTED,     simple, gen_out_octets_encrypted,  out-octets-encrypted, /macsec/generation) \
 \
/* These are combined counters because the SNMP MIB also \
 * has octet counters for these values in secyTxSCStatsTable. \
 *    secyTxSCStatsProtectedPkts(1), \
 *    secyTxSCStatsEncryptedPkts(4) \
 *    secyTxSCStatsOctetsProtected(10), \
 *    secyTxSCStatsOctetsEncrypted(11) \
 */ \
_(GEN_SC_PKTS_PROTECTED, combined, txsc_out_pkts_protected, out-pkts-protected,   /macsec/generation/txsc) \
_(GEN_SC_PKTS_ENCRYPTED, combined, txsc_out_pkts_encrypted, out-pkts-encrypted,   /macsec/generation/txsc) \

/* These counters are identified by an IPsec SA index, instead of an
 * interface index
 */
# define foreach_macsec_sa_counter \
/* SNMP MIB only (secyRxSAStatsTable) \
 *     secyRxSAStatsUnusedSAPkts, secyRxSAStatsNoUsingSAPkts, \
 *     secyRxSAStatsNotValidPkts, secyRxSAStatsInvalidPkts, \
 *     secyRxSAStatsOKPkts \
 */ \
_(VER_SA_PKTS_UNUSED,    simple, rxsa_in_pkts_unused_sa,    in-pkts-unused-sa,    /macsec/verification/rxsa) \
_(VER_SA_PKTS_NO_USING,  simple, rxsa_in_ptks_no_using_sa,  in-pkts-no-using-sa,  /macsec/verification/rxsa) \
_(VER_SA_PKTS_NOT_VALID, simple, rxsa_in_pkts_not_valid,    in-pkts-not-valid,    /macsec/verification/rxsa) \
_(VER_SA_PKTS_INVALID,   simple, rxsa_in_pkts_invalid,      in-pkts-invalid,      /macsec/verification/rxsa) \
_(VER_SA_PKTS_OK,        simple, rxsa_in_pkts_ok,           in-pkts-ok,           /macsec/verification/rxsa) \
/* SNMP MIB only (secyTxSAStatsTable) \
 * secyTxSAStatsProtectedPkts \
 * secyTxSAStatsEncryptedPkts \
 */ \
_(GEN_SA_PKTS_PROTECTED, simple, txsa_out_pkts_protected,   out-pkts-encrypted,   /macsec/generation/txsa) \
_(GEN_SA_PKTS_ENCRYPTED, simple, txsa_out_pkts_encrypted,   out-pkts-encrypted,   /macsec/generation/txsa)

# define foreach_macsec_all_counters \
foreach_macsec_counter \
foreach_macsec_sa_counter

# define MACSEC_INC_SIMPLE_COUNTER(field, thr_index, index, value) \
    vlib_increment_simple_counter(&macsec_main.counters.field, \
                                  thr_index, index, value)
# define MACSEC_INC_COMBINED_COUNTER(field, thr_index, index, pkts, bytes) \
    vlib_increment_combined_counter(&macsec_main.counters.field, \
                                    thr_index, index, pkts, bytes)

void macsec_validate_counters (u32, u32);

#else

# define MACSEC_INC_SIMPLE_COUNTER(field, thr_index, index, value) \
  (void)thr_index
# define MACSEC_INC_COMBINED_COUNTER(field, thr_index, index, pkts, bytes) \
  (void)thr_index
# define macsec_validate_counters(a,b)

#endif

typedef struct {
    BVT(clib_bihash)		decrypt_sa_table;	/* map SCI -> SA */
    BVT(clib_bihash)		encrypt_sa_table;	/* map SCI -> SA */
    macsec_per_thread_data_t	*ptd;

    clib_spinlock_t		decrypt_sa_table_lock;
    clib_spinlock_t		encrypt_sa_table_lock;
    u8				crypto_backend_present;
    u32				encrypt_async_post_next;
    u32				decrypt_async_post_next;

    u32				macsec_encrypt_fq_index;
    u32				macsec_decrypt_fq_index;

    /*
     * IPSEC esp backend selection also selects MACSEC backend, which
     * in turn implies a backend-specific node for encrypting outbound
     * packets. IPSEC notifies MACSEC when the backend changes, and
     * we track the encryption node here.
     *
     * ETFS gets notified by MACSEC when the backend changes and
     * grabs this encryption node identity from MACSEC.
     */
    u32				macsec_encrypt_node_index;

    etfs3_backend_update_cb_t	etfs3_backend_update_cb;

#ifdef MACSEC_COUNTERS_ENABLE
# define _(sym, typ, field, name, statname) vlib_##typ##_counter_main_t field;
    struct {
        foreach_macsec_all_counters
    } counters;
# undef _
#endif
} macsec_main_t;

extern macsec_main_t	macsec_main;

typedef struct {
    u16		ethertype;
    u8		tci_an;
    u8		short_length;
    u32		pn;

    /*
     * The following part (Secure Channel Identifier, SCI) is optional on
     * the wire for point-to-point, but is included in the cryptographic
     * computation (see IEEE 802.1AE-2006 section 9.9)
     */
    union {
	struct {
	    u8	sysid[6];
	    u16	portid;
	};
	u64	sci;
	u8	sci_bytes[8];
    };
} macsec_sectag_t;

#define MACSEC_TAG_NOSCI_LENGTH		8	/* bytes */
#define MACSEC_TAG_WITHSCI_LENGTH	16	/* bytes */

#define MACSEC_ETYPE			0x88e5

/*
 * TCI_AN bits:
 *
 * V = 0	version 0
 * ES = 1	end station: yes
 * SC = 0	SCI not present
 * SCB = 0	No Single Copy Broadcast
 * E = 1	Encryption
 * C = 1	Changed Text
 * AN = 0	Association Number
 *
 * Note: ES==1 && SCB==0 implies portid=00-01
 */
#define MACSEC_TCI_FLAG_V	0x80
#define MACSEC_TCI_FLAG_ES	0x40
#define MACSEC_TCI_FLAG_SC	0x20
#define MACSEC_TCI_FLAG_SCB	0x10
#define MACSEC_TCI_FLAG_E	0x08
#define MACSEC_TCI_FLAG_C	0x04
#define MACSEC_TCI_AN_MASK	0x03

#define MACSEC_TCI_AN_DEFAULT	( \
    MACSEC_TCI_FLAG_ES | MACSEC_TCI_FLAG_E | MACSEC_TCI_FLAG_C )

#define MACSEC_SL_ZERO_MASK	0xc0
#define MACSEC_SL_MASK		0x3f

/*
 * AAD (associated data)
 *
 *	6	dst addr
 *	6	src addr
 *	2	macsec etype
 *	1	TCI_AN
 *	1	SL
 *	4	packet number
 *	8	SCI
 */
#define MACSEC_AAD_LENGTH	28



/*
 * macsec data stored in buffer opaque area(s) for async crypto.
 */

/* encryption path needs only next_index */
typedef union
{
    u16 next_index;
} macsec_post_data_t;

STATIC_ASSERT (sizeof (macsec_post_data_t) <=
    STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
    "Custom meta-data too large for vnet_buffer_opaque_t");

#define macsec_post_data(b)				\
    ((macsec_post_data_t *)((u8 *)((b)->opaque)		\
     + STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

extern u8 *format_macsec_header(u8 *s, va_list *args);

extern int macsec_enabled(void);

extern void macsec_backend_update(vlib_main_t *vm);

extern vlib_node_registration_t macsec_encrypt_node;
extern vlib_node_registration_t macsec_decrypt_node;

#endif /* __MACSEC_H__ */

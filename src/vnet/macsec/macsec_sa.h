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

#ifndef __MACSEC_SA_H__
#define __MACSEC_SA_H__

#include <vlib/vlib.h>

#define foreach_macsec_crypto_alg   \
  _ (0, NONE, "none")               \
  _ (1, AES_GCM_128, "aes-gcm-128") \
  _ (2, AES_GCM_256, "aes-gcm-256")

typedef enum
{
#define _(v, f, s) MACSEC_CRYPTO_ALG_##f = v,
  foreach_macsec_crypto_alg
#undef _
    MACSEC_CRYPTO_N_ALG,
} macsec_crypto_alg_t;

#define MACSEC_CRYPTO_ALG_IS_GCM(_alg)                     \
  (((_alg == MACSEC_CRYPTO_ALG_AES_GCM_128) ||             \
    (_alg == MACSEC_CRYPTO_ALG_AES_GCM_256)))



#define MACSEC_KEY_MAX_LEN 128
typedef struct macsec_key_t_
{
  u8 len;
  u8 data[MACSEC_KEY_MAX_LEN];
} macsec_key_t;

#define foreach_macsec_sa_flags				\
    _ (0, NONE, "none")					\
    _ (1, IS_INBOUND, "inbound")			\
    _ (2, USE_ANTI_REPLAY, "anti-replay")

typedef enum macsec_sad_flags_t_
{
#define _(v, f, s) MACSEC_SA_FLAG_##f = v,
    foreach_macsec_sa_flags
#undef _
} __clib_packed macsec_sa_flags_t;

STATIC_ASSERT (sizeof (macsec_sa_flags_t) == 1, "MACSEC SA flags > 1 byte");


typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    macsec_sa_flags_t	flags;
    u8			spare;
    u8			ether_addr[6];	/* local or remote depending on dir */
    u32			if_index;	/* tx or rx encrypted PDUs here */
    u32			ipsec_sa_index;
    u32			replay_window;


    /* data accessed by dataplane code should be above this comment */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

    macsec_crypto_alg_t	crypto_alg;
    macsec_key_t	crypto_key;

} macsec_sa_t;

/*
 * ID values for macsec_sa_add():
 *
 * 32-bit value is part of the ipsec SA id space. ipsec sets a bit in the
 * upper 8 bits to indicate the ID is a macsec ID.
 *
 *  3               2               1
 *  1               3               5               7             0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  not allowed  | reserve below |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Callers of macsec_sa_add() may set only the lower 24 bits. Callers
 * can reserve the upper 8 bits of these 24 bits below.
 */
#define MACSEC_SA_ID_ALLOWED_BITS	0x00ffffff
#define MACSEC_SA_ID_ETFS_ENCAP		0x00020000
#define MACSEC_SA_ID_ETFS_DECAP		0x00010000

/* for both rx and tx */
extern int
macsec_sa_add(u32 id, macsec_sa_t *new_sa, u32 *out_sa_index);

extern void
macsec_mk_key (macsec_key_t * key, const u8 * data, u8 len);

extern u32
macsec_get_ipsec_sa_index(u32 macsec_sa_index);

extern void
macsec_sa_delete(u32 sa_index);

#endif /* __MACSEC_SA_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

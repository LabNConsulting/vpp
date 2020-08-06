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
#include <vnet/macsec/macsec_format.h>

static u8 *
format_macsec_header_internal(int force_sc, u8 *s, va_list *args)
{
    u8	*pkt = va_arg (*args, u8 *);
    u8	tcian = pkt[14];
    u32	pn;
    u32 indent = format_get_indent (s);

    clib_memcpy(&pn, pkt + 16, sizeof(pn));

    s = format(s,
	"MACSEC: dst %U, src %U, etype 0x%x\n"
	"%Utci V%c,ES%c,SC%c,SCB%c,E%c,C%c,AN%u\n",
	format_ethernet_address, pkt,
	format_ethernet_address, pkt+6,
	clib_net_to_host_u16(*(u16 *)(pkt+12)),
	format_white_space, indent+2,
	((tcian & MACSEC_TCI_FLAG_V)? '1': '0'),
	((tcian & MACSEC_TCI_FLAG_ES)? '1': '0'),
	((tcian & MACSEC_TCI_FLAG_SC)? '1': '0'),
	((tcian & MACSEC_TCI_FLAG_SCB)? '1': '0'),
	((tcian & MACSEC_TCI_FLAG_E)? '1': '0'),
	((tcian & MACSEC_TCI_FLAG_C)? '1': '0'),
	tcian & MACSEC_TCI_AN_MASK);

    s = format(s, "%Usl %u, zero %u, pn %u",
	format_white_space, indent+2,
	pkt[15] & MACSEC_SL_MASK,
	pkt[15] & MACSEC_SL_ZERO_MASK,
	clib_net_to_host_u32(pn));

    if (force_sc || (tcian & MACSEC_TCI_FLAG_SC)) {
	s = format(s, ", SCI %U %u\n",
	    format_ethernet_address, pkt + 20,
	    clib_net_to_host_u16(*(u16 *)(pkt+26)));
    } else {
	s = format(s, "\n");
    }

    return s;
}

u8 *
format_macsec_header(u8 *s, va_list *args)
{
    return format_macsec_header_internal(0, s, args);
}

u8 *
format_macsec_header_force_sc(u8 *s, va_list *args)
{
    return format_macsec_header_internal(1, s, args);
}

ipsec_crypto_alg_t
macsec_map_crypto_alg_to_ipsec(macsec_crypto_alg_t macsec_crypto_alg)
{
    switch (macsec_crypto_alg) {
    case MACSEC_CRYPTO_ALG_AES_GCM_128:
	return IPSEC_CRYPTO_ALG_AES_GCM_128;
    case MACSEC_CRYPTO_ALG_AES_GCM_256:
	return IPSEC_CRYPTO_ALG_AES_GCM_256;
    case MACSEC_CRYPTO_ALG_NONE:
	return IPSEC_CRYPTO_ALG_NONE;
    default:
	ASSERT(0);
    }
    /* must be one of the above */
    ASSERT(0);
    return IPSEC_CRYPTO_ALG_NONE;	/* silence compiler warning */
}

uword
unformat_macsec_crypto_alg (unformat_input_t * input, va_list * args)
{
    u32 *r = va_arg (*args, u32 *);

    if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = MACSEC_CRYPTO_ALG_##f;
    foreach_macsec_crypto_alg
#undef _
	else
	return 0;
    return 1;
}

uword
unformat_macsec_key (unformat_input_t * input, va_list * args)
{
    macsec_key_t *key = va_arg (*args, macsec_key_t *);
    u8 *data;

    if (unformat (input, "%U", unformat_hex_string, &data)) {
	macsec_mk_key (key, data, vec_len (data));
	vec_free (data);
	return 1;
    }
    return 0;
}

uword
unformat_etfs_macsec_sa_config(unformat_input_t *input, va_list *args)
{
    macsec_sa_t		*conf = va_arg (*args, macsec_sa_t *);

    macsec_crypto_alg_t	crypto_alg;
    macsec_key_t	txkey = { 0 };
    macsec_key_t	rxkey = { 0 };
    u32			replay_window = 0;
    int			set_replay_window = 0;

    crypto_alg = MACSEC_CRYPTO_ALG_NONE;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {

	if (unformat (input, "crypto-alg %U",
	    unformat_macsec_crypto_alg, &crypto_alg)) {
	    ;
	} else if (unformat (input, "tx-crypto-key %U",
	    unformat_macsec_key, &txkey)) {
	    ;
	} else if (unformat (input, "rx-crypto-key %U",
	    unformat_macsec_key, &rxkey)) {
	    ;
	} else if (unformat (input, "replay-window %u",
	    &replay_window)) {
	    set_replay_window = 1;
	} else {
	    return 0;
        }
    }

    if (txkey.len && rxkey.len) {
	clib_warning ("Only one of tx-crypto-key or rx-crypto-key "
	    "may be specified");
	return 0;
    }

    memset(conf, 0, sizeof(*conf));

    if (rxkey.len) {
	conf->flags |= MACSEC_SA_FLAG_IS_INBOUND;
	conf->crypto_key = rxkey;
    }
    if (txkey.len) {
	conf->crypto_key = txkey;
    }

    conf->crypto_alg = crypto_alg;

    if (set_replay_window) {
	conf->flags |= MACSEC_SA_FLAG_USE_ANTI_REPLAY;
	conf->replay_window = replay_window;
    }

    return 1;
}

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

#ifndef __MACSEC_FORMAT_H__
#define __MACSEC_FORMAT_H__

#include <vnet/macsec/macsec_sa.h>
#include <vnet/crypto/crypto.h>
#include <vnet/ipsec/ipsec_sa.h>

extern u8 *
format_macsec_header(u8 *s, va_list *args);

extern u8 *
format_macsec_header_force_sc(u8 *s, va_list *args);

extern ipsec_crypto_alg_t
macsec_map_crypto_alg_to_ipsec(macsec_crypto_alg_t macsec_crypto_alg);

extern uword
unformat_macsec_crypto_alg (unformat_input_t * input, va_list * args);

extern uword
unformat_macsec_key (unformat_input_t * input, va_list * args);

extern uword
unformat_etfs_macsec_sa_config(unformat_input_t *input, va_list *args);

#endif /* __MACSEC_FORMAT_H__ */

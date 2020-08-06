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

#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>

#include <vnet/macsec/macsec_sa.h>

#define DECRYPT_FLOW_TBL_NUM_BUCKETS	32
#define DECRYPT_FLOW_TBL_MEMORY_SIZE	(20*1024)

typedef struct {
    BVT(clib_bihash)	decrypt_sa_table;	/* map SCI -> SA */

    clib_spinlock_t	decrypt_sa_table_lock;
    u8			crypto_backend_present;
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

extern u8 *format_macsec_header(u8 *s, va_list *args);

extern int macsec_enabled(void);

#endif /* __MACSEC_H__ */

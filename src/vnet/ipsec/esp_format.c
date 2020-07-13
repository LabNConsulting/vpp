/*
 * esp_format.c : ESP format
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vnet/api_errno.h>
#include <vnet/ipsec/esp.h>
#include <plugins/iptfs/ipsec_iptfs.h>

u8 *
format_esp_header (u8 * s, va_list * args)
{
  esp_header_t *esp = va_arg (*args, esp_header_t *);
  u32 spi = clib_net_to_host_u32 (esp->spi);

  s = format (s, "ESP: spi %u (0x%08x), seq %u",
	      spi, spi, clib_net_to_host_u32 (esp->seq));
  return s;
}

/* packet trace format function */
u8 *
format_iptfs_header (u8 * s, va_list * args)
{
  ipsec_iptfs_header_t *h = va_arg (*args, ipsec_iptfs_header_t *);
  if (h->basic.subtype == IPTFS_SUBTYPE_CC)
    {
      u32 r, a, x;
      iptfs_cc_get_rtt_and_delays(&h->cc, &r, &a, &x);

      s =
	format (s,
		"TFS CC Header: subtype: %x flags %x offset %u rtt %u actual-delay %u xmit-delay %u timeval %u timeecho %u loss_rate %u",
		h->cc.subtype, h->cc.flags, clib_net_to_host_u16 (h->cc.block_offset), r, a, x, h->cc.tval, h->cc.techo, clib_net_to_host_u32 (h->cc.loss_rate)
                );
    }
  else
    {
      s = format (s, "IPTFS Basic Header: subtype: %x resv %x offset %u",
		  h->basic.subtype, h->basic.resv,
		  clib_net_to_host_u16 (h->basic.block_offset));
    }
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

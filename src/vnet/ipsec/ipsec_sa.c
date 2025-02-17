/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vppinfra/time.h>

/**
 * @brief
 * SA packet & bytes counters
 */
vlib_combined_counter_main_t ipsec_sa_counters = {
  .name = "SA",
  .stat_segment_name = "/net/ipsec/sa",
};

static clib_error_t *
ipsec_call_add_del_callbacks (ipsec_main_t * im, ipsec_sa_t * sa,
			      u32 sa_index, int is_add)
{
  ipsec_ah_backend_t *ab;
  ipsec_esp_backend_t *eb;
  switch (sa->protocol)
    {
    case IPSEC_PROTOCOL_AH:
      ab = pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      if (ab->add_del_sa_sess_cb)
	return ab->add_del_sa_sess_cb (sa_index, is_add);
      break;
    case IPSEC_PROTOCOL_ESP:
      eb = pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      if (eb->add_del_sa_sess_cb)
	return eb->add_del_sa_sess_cb (sa_index, is_add);
      break;
    }
  return 0;
}

void
ipsec_mk_key (ipsec_key_t * key, const u8 * data, u8 len)
{
  memset (key, 0, sizeof (*key));

  if (len > sizeof (key->data))
    key->len = sizeof (key->data);
  else
    key->len = len;

  memcpy (key->data, data, key->len);
}

/**
 * 'stack' (resolve the recursion for) the SA tunnel destination
 */
static void
ipsec_sa_stack (ipsec_sa_t * sa)
{
  ipsec_main_t *im = &ipsec_main;
  fib_forward_chain_type_t fct;
  dpo_id_t tmp = DPO_INVALID;

  fct =
    fib_forw_chain_type_from_fib_proto ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
					 FIB_PROTOCOL_IP6 :
					 FIB_PROTOCOL_IP4));

  fib_entry_contribute_forwarding (sa->fib_entry_index, fct, &tmp);

  if (IPSEC_PROTOCOL_AH == sa->protocol)
    dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			  im->ah6_encrypt_node_index :
			  im->ah4_encrypt_node_index), &sa->dpo, &tmp);
  else
    dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			  im->esp6_encrypt_node_index :
			  im->esp4_encrypt_node_index), &sa->dpo, &tmp);
  dpo_reset (&tmp);
}

void
ipsec_sa_set_crypto_alg (ipsec_sa_t * sa, ipsec_crypto_alg_t crypto_alg)
{
  ipsec_main_t *im = &ipsec_main;
  sa->crypto_alg = crypto_alg;
  sa->crypto_iv_size = im->crypto_algs[crypto_alg].iv_size;
  sa->esp_block_align = clib_max (4, im->crypto_algs[crypto_alg].block_align);
  sa->sync_op_data.crypto_enc_op_id = im->crypto_algs[crypto_alg].enc_op_id;
  sa->sync_op_data.crypto_dec_op_id = im->crypto_algs[crypto_alg].dec_op_id;
  sa->crypto_calg = im->crypto_algs[crypto_alg].alg;
  ASSERT (sa->crypto_iv_size <= ESP_MAX_IV_SIZE);
  ASSERT (sa->esp_block_align <= ESP_MAX_BLOCK_SIZE);
  if (IPSEC_CRYPTO_ALG_IS_GCM (crypto_alg))
    {
      sa->integ_icv_size = im->crypto_algs[crypto_alg].icv_size;
      ipsec_sa_set_IS_AEAD (sa);
    }
}

void
ipsec_sa_set_integ_alg (ipsec_sa_t * sa, ipsec_integ_alg_t integ_alg)
{
  ipsec_main_t *im = &ipsec_main;
  sa->integ_alg = integ_alg;
  sa->integ_icv_size = im->integ_algs[integ_alg].icv_size;
  sa->sync_op_data.integ_op_id = im->integ_algs[integ_alg].op_id;
  sa->integ_calg = im->integ_algs[integ_alg].alg;
  ASSERT (sa->integ_icv_size <= ESP_MAX_ICV_SIZE);
}

void
ipsec_sa_set_async_op_ids (ipsec_sa_t * sa)
{
  /* *INDENT-OFF* */
  if (ipsec_sa_is_set_USE_ESN (sa))
    {
#define _(n, s, k) \
  if( sa->sync_op_data.crypto_enc_op_id == VNET_CRYPTO_OP_##n##_ENC ) \
    sa->async_op_data.crypto_async_enc_op_id = \
      VNET_CRYPTO_OP_##n##_TAG16_AAD12_ENC; \
  if( sa->sync_op_data.crypto_dec_op_id == VNET_CRYPTO_OP_##n##_DEC ) \
    sa->async_op_data.crypto_async_dec_op_id = \
      VNET_CRYPTO_OP_##n##_TAG16_AAD12_DEC;
    foreach_crypto_aead_alg
#undef _
    }
  else
    {
#define _(n, s, k) \
  if( sa->sync_op_data.crypto_enc_op_id == VNET_CRYPTO_OP_##n##_ENC ) \
    sa->async_op_data.crypto_async_enc_op_id = \
      VNET_CRYPTO_OP_##n##_TAG16_AAD8_ENC; \
  if( sa->sync_op_data.crypto_dec_op_id == VNET_CRYPTO_OP_##n##_DEC ) \
    sa->async_op_data.crypto_async_dec_op_id = \
      VNET_CRYPTO_OP_##n##_TAG16_AAD8_DEC;
    foreach_crypto_aead_alg
#undef _
    }

#define _(c, h, s, k ,d) \
  if( sa->sync_op_data.crypto_enc_op_id == VNET_CRYPTO_OP_##c##_ENC && \
      sa->sync_op_data.integ_op_id == VNET_CRYPTO_OP_##h##_HMAC) \
    sa->async_op_data.crypto_async_enc_op_id = \
      VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC; \
  if( sa->sync_op_data.crypto_dec_op_id == VNET_CRYPTO_OP_##c##_DEC && \
      sa->sync_op_data.integ_op_id == VNET_CRYPTO_OP_##h##_HMAC) \
    sa->async_op_data.crypto_async_dec_op_id = \
      VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC;
  foreach_crypto_link_async_alg
#undef _
  /* *INDENT-ON* */
}

int
ipsec_sa_add_and_lock (u32 id,
		       u32 spi,
		       ipsec_protocol_t proto,
		       ipsec_crypto_alg_t crypto_alg,
		       const ipsec_key_t * ck,
		       ipsec_integ_alg_t integ_alg,
		       const ipsec_key_t * ik,
		       ipsec_sa_flags_t flags,
		       u32 originator,
		       u8 _tfs_type,
		       void *tfs_config,
		       u32 tx_table_id,
		       u32 salt,
		       const ip46_address_t * tun_src,
		       const ip46_address_t * tun_dst, u32 * sa_out_index,
		       u16 src_port, u16 dst_port)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  clib_error_t *err;
  ipsec_sa_t *sa;
  u32 sa_index;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (p)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  ASSERT(!(id & IPSEC_SA_ID_MACSEC));

  pool_get_aligned_zero (im->sad, sa, CLIB_CACHE_LINE_BYTES);

  fib_node_init (&sa->node, FIB_NODE_TYPE_IPSEC_SA);
  fib_node_lock (&sa->node);
  sa_index = sa - im->sad;

  vlib_validate_combined_counter (&ipsec_sa_counters, sa_index);
  vlib_zero_combined_counter (&ipsec_sa_counters, sa_index);

  sa->id = id;
  sa->spi = spi;
  sa->stat_index = sa_index;
  sa->protocol = proto;
  sa->flags = flags;
  sa->originator = originator;
  sa->tfs_type = _tfs_type;
  sa->salt = salt;
  sa->encrypt_thread_index = (vlib_num_workers ())? ~0 : 0;
  sa->decrypt_thread_index = (vlib_num_workers ())? ~0 : 0;
  sa->created_time_ns = unix_time_now_nsec();
  if (integ_alg != IPSEC_INTEG_ALG_NONE)
    {
      ipsec_sa_set_integ_alg (sa, integ_alg);
      clib_memcpy (&sa->integ_key, ik, sizeof (sa->integ_key));
    }
  ipsec_sa_set_crypto_alg (sa, crypto_alg);
  ipsec_sa_set_async_op_ids (sa);

  clib_memcpy (&sa->crypto_key, ck, sizeof (sa->crypto_key));
  ip46_address_copy (&sa->tunnel_src_addr, tun_src);
  ip46_address_copy (&sa->tunnel_dst_addr, tun_dst);

  sa->crypto_key_index = vnet_crypto_key_add (vm,
					      im->crypto_algs[crypto_alg].alg,
					      (u8 *) ck->data, ck->len);
  if (~0 == sa->crypto_key_index)
    {
      pool_put (im->sad, sa);
      return VNET_API_ERROR_KEY_LENGTH;
    }

  if (integ_alg != IPSEC_INTEG_ALG_NONE)
    {
      sa->integ_key_index = vnet_crypto_key_add (vm,
						 im->
						 integ_algs[integ_alg].alg,
						 (u8 *) ik->data, ik->len);
      if (~0 == sa->integ_key_index)
	{
	  pool_put (im->sad, sa);
	  return VNET_API_ERROR_KEY_LENGTH;
	}
    }

  if (sa->async_op_data.crypto_async_enc_op_id &&
      !ipsec_sa_is_set_IS_AEAD (sa))
    {				//AES-CBC & HMAC
      sa->async_op_data.linked_key_index =
	vnet_crypto_key_add_linked (vm, sa->crypto_key_index,
				    sa->integ_key_index);
    }

  if (im->async_mode)
    sa->crypto_op_data = sa->async_op_data.data;
  else
    sa->crypto_op_data = sa->sync_op_data.data;

  err = ipsec_check_support_cb (im, sa);
  if (err)
    {
      clib_warning ("%s", err->what);
      pool_put (im->sad, sa);
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  if (sa->tfs_type != IPSEC_SA_TFS_TYPE_NO_TFS)
    {
      if (!im->tfs_check_support_cb
	  || (err = im->tfs_check_support_cb (sa, tfs_config)))
	{
	  clib_warning ("No TFS support");
	  pool_put (im->sad, sa);
	  return VNET_API_ERROR_UNIMPLEMENTED;
	}
      /* tfs_check_support_cb may update tfs_type in the SA to disable it */
      if (sa->tfs_type != _tfs_type)
	clib_warning ("TFS disabled outbound due to no config");
    }

  err = ipsec_call_add_del_callbacks (im, sa, sa_index, 1);
  if (!err && im->tfs_add_del_sa_cb)
    err = im->tfs_add_del_sa_cb (sa_index, tfs_config, 1);
  if (err)
    {
      pool_put (im->sad, sa);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }


  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    {
      fib_protocol_t fproto = (ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			       FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
      fib_prefix_t pfx = {
	.fp_addr = sa->tunnel_dst_addr,
	.fp_len = (ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ? 128 : 32),
	.fp_proto = fproto,
      };
      sa->tx_fib_index = fib_table_find (fproto, tx_table_id);
      if (sa->tx_fib_index == ~((u32) 0))
	{
	  pool_put (im->sad, sa);
	  return VNET_API_ERROR_NO_SUCH_FIB;
	}

      sa->fib_entry_index = fib_entry_track (sa->tx_fib_index,
					     &pfx,
					     FIB_NODE_TYPE_IPSEC_SA,
					     sa_index, &sa->sibling);
      ipsec_sa_stack (sa);

      /* generate header templates */
      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	{
	  sa->ip6_hdr.ip_version_traffic_class_and_flow_label = 0x60;
	  sa->ip6_hdr.hop_limit = 254;
	  sa->ip6_hdr.src_address.as_u64[0] =
	    sa->tunnel_src_addr.ip6.as_u64[0];
	  sa->ip6_hdr.src_address.as_u64[1] =
	    sa->tunnel_src_addr.ip6.as_u64[1];
	  sa->ip6_hdr.dst_address.as_u64[0] =
	    sa->tunnel_dst_addr.ip6.as_u64[0];
	  sa->ip6_hdr.dst_address.as_u64[1] =
	    sa->tunnel_dst_addr.ip6.as_u64[1];
	  if (ipsec_sa_is_set_UDP_ENCAP (sa))
	    sa->ip6_hdr.protocol = IP_PROTOCOL_UDP;
	  else
	    sa->ip6_hdr.protocol = IP_PROTOCOL_IPSEC_ESP;
	}
      else
	{
	  sa->ip4_hdr.ip_version_and_header_length = 0x45;
	  sa->ip4_hdr.ttl = 254;
	  sa->ip4_hdr.src_address.as_u32 = sa->tunnel_src_addr.ip4.as_u32;
	  sa->ip4_hdr.dst_address.as_u32 = sa->tunnel_dst_addr.ip4.as_u32;

	  if (ipsec_sa_is_set_UDP_ENCAP (sa))
	    sa->ip4_hdr.protocol = IP_PROTOCOL_UDP;
	  else
	    sa->ip4_hdr.protocol = IP_PROTOCOL_IPSEC_ESP;
	  sa->ip4_hdr.checksum = ip4_header_checksum (&sa->ip4_hdr);
	}
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      if (dst_port == IPSEC_UDP_PORT_NONE)
	sa->udp_hdr.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      else
	sa->udp_hdr.dst_port = clib_host_to_net_u16 (dst_port);

      if (src_port == IPSEC_UDP_PORT_NONE)
	sa->udp_hdr.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      else
	sa->udp_hdr.src_port = clib_host_to_net_u16 (src_port);

      if (ipsec_sa_is_set_IS_INBOUND (sa))
	ipsec_register_udp_port (clib_host_to_net_u16 (sa->udp_hdr.dst_port));
    }

  hash_set (im->sa_index_by_sa_id, sa->id, sa_index);

  if (sa_out_index)
    *sa_out_index = sa_index;

  return (0);
}

/*
 * Cryptodev infrastructure is owned by ipsec, so we allocate an ipsec SA
 * and use it for macsec as well.
 */
int
ipsec_sa_macsec_add(
    u32			macsec_id,
    ipsec_crypto_alg_t	crypto_alg,
    const ipsec_key_t	*ck,
    u8			is_inbound,		/* not sure if needed */
    u8			replay_protect,		/* !0 => enable replay check */
    u32			replay_window,
    u32			*sa_out_index)
{
  vlib_main_t	*vm = vlib_get_main ();
  ipsec_main_t	*im = &ipsec_main;
  u32		id = IPSEC_SA_ID_MACSEC | macsec_id;
  ipsec_sa_t	*sa;
  uword		*p;
  u32		sa_index;

  vnet_crypto_async_op_id_t		async_enc_op_id;
  vnet_crypto_async_op_id_t		async_dec_op_id;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (p)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  /*
   * macsec allows only a few crypto algorithms
   */
  switch (crypto_alg) {
  case IPSEC_CRYPTO_ALG_AES_GCM_128:
	async_enc_op_id = VNET_CRYPTO_OP_AES_128_GCM_TAG16_AAD28_ENC;
	async_dec_op_id = VNET_CRYPTO_OP_AES_128_GCM_TAG16_AAD28_DEC;
	break;
  case IPSEC_CRYPTO_ALG_AES_GCM_256:
	async_enc_op_id = VNET_CRYPTO_OP_AES_256_GCM_TAG16_AAD28_ENC;
	async_dec_op_id = VNET_CRYPTO_OP_AES_256_GCM_TAG16_AAD28_DEC;
	break;
    break;
  default:
    return VNET_API_ERROR_INVALID_ALGORITHM;
  }

  pool_get_aligned_zero (im->sad, sa, CLIB_CACHE_LINE_BYTES);
  sa_index = sa - im->sad;

  vlib_validate_combined_counter (&ipsec_sa_counters, sa_index);
  vlib_zero_combined_counter (&ipsec_sa_counters, sa_index);

  if (replay_protect) {
    sa->flags |= IPSEC_SA_FLAG_USE_ANTI_REPLAY;
    sa->replay_macsec.window_size = replay_window;
  }
  if (is_inbound)
    sa->flags |= IPSEC_SA_FLAG_IS_INBOUND;

  sa->id = id;

  sa->encrypt_thread_index = (vlib_num_workers ())? ~0 : 0;
  sa->decrypt_thread_index = (vlib_num_workers ())? ~0 : 0;

  sa->created_time_ns = unix_time_now_nsec();
  ipsec_sa_set_crypto_alg (sa, crypto_alg);
  sa->async_op_data.crypto_async_enc_op_id = async_enc_op_id;
  sa->async_op_data.crypto_async_dec_op_id = async_dec_op_id;

  if (im->async_mode)
    sa->crypto_op_data = sa->async_op_data.data;
  else
    sa->crypto_op_data = sa->sync_op_data.data;

  clib_memcpy (&sa->crypto_key, ck, sizeof (sa->crypto_key));

  sa->crypto_key_index = vnet_crypto_key_add (vm,
					      im->crypto_algs[crypto_alg].alg,
					      (u8 *) ck->data, ck->len);
  if (~0 == sa->crypto_key_index)
    {
      pool_put (im->sad, sa);
      return VNET_API_ERROR_KEY_LENGTH;
    }

  hash_set (im->sa_index_by_sa_id, sa->id, sa_index);

  if (sa_out_index)
    *sa_out_index = sa_index;

  return 0;
}

static void
ipsec_sa_del (ipsec_sa_t * sa)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  u32 sa_index;

  sa_index = sa - im->sad;
  hash_unset (im->sa_index_by_sa_id, sa->id);

  /* no recovery possible when deleting an SA */
  (void) ipsec_call_add_del_callbacks (im, sa, sa_index, 0);

  if (ipsec_sa_is_set_UDP_ENCAP (sa) && ipsec_sa_is_set_IS_INBOUND (sa))
    ipsec_unregister_udp_port (clib_net_to_host_u16 (sa->udp_hdr.dst_port));

  if (im->tfs_add_del_sa_cb)
    (void)im->tfs_add_del_sa_cb (sa_index, NULL, 0);

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    {
      fib_entry_untrack (sa->fib_entry_index, sa->sibling);
      dpo_reset (&sa->dpo);
    }

  vnet_crypto_key_del (vm, sa->crypto_key_index);
  if (sa->integ_alg != IPSEC_INTEG_ALG_NONE)
    vnet_crypto_key_del (vm, sa->integ_key_index);
  pool_put (im->sad, sa);
}

void
ipsec_sa_macsec_del(u32 sa_index)
{
  ipsec_main_t	*im = &ipsec_main;
  ipsec_sa_t	*sa;

  sa = im->sad + sa_index;
  ASSERT(ipsec_sa_is_MACSEC(sa));
  ipsec_sa_del(sa);
}


u32
ipsec_sa_get_sw_if_index (vnet_main_t * vnm, u32 sa_index)
{
#if 0
  ipsec_tunnel_if_t *t;
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;
  uword *p;

  sa = pool_elt_at_index (im->sad, sa_index);
  if (!ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      clib_warning ("%s: Can't set MTU on non-tunnel!", __FUNCTION__);
      return (u32) ~ 0;
    }
  if (!ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
    {
      ipsec4_tunnel_key_t key4;
      u32 pv;
      key4.remote_ip.as_u32 = sa->tunnel_dst_addr.ip4.as_u32;
      key4.spi = clib_host_to_net_u32 (sa->spi);
      p = hash_get (im->ipsec4_if_pool_index_by_key, key4.as_u64);
      if (!p)
        {
          clib_warning("%s: hash table nelts %u",
                       __FUNCTION__, hash_elts (im->ipsec4_if_pool_index_by_key));
          hash_foreach (key4.as_u64,
                        pv,
                        im->ipsec4_if_pool_index_by_key,
                        ({clib_warning
                            ("%s: key ip %U key spi %u value %u",
                             __FUNCTION__,
                             format_ip4_address,
                             &key4.remote_ip,
                             key4.spi, pv);}));
        }
    }
  else
    {
      ipsec6_tunnel_key_t key6;
      key6.remote_ip = sa->tunnel_dst_addr.ip6;
      key6.spi = clib_host_to_net_u32 (sa->spi);
      p = hash_get_mem (im->ipsec6_if_pool_index_by_key, &key6);
    }
  if (!p)
    {
      clib_warning
	("%s: Can't get IPsec tunnel interface sa_index %u spi %u!",
	 __FUNCTION__, sa_index, sa->spi);
      return (u32) ~ 0;
    }
  t = pool_elt_at_index (im->tunnel_interfaces, *p);
  return t->sw_if_index;
#else
  return ~0;
#endif
}

void
ipsec_sa_unlock (index_t sai)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;

  if (INDEX_INVALID == sai)
    return;

  sa = pool_elt_at_index (im->sad, sai);

  fib_node_unlock (&sa->node);
}

void
ipsec_sa_lock (index_t sai)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;

  if (INDEX_INVALID == sai)
    return;

  sa = pool_elt_at_index (im->sad, sai);

  fib_node_lock (&sa->node);
}

index_t
ipsec_sa_find_and_lock (u32 id)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return INDEX_INVALID;

  sa = pool_elt_at_index (im->sad, p[0]);

  fib_node_lock (&sa->node);

  return (p[0]);
}

int
ipsec_sa_unlock_id (u32 id)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  ipsec_sa_unlock (p[0]);

  return (0);
}

void
ipsec_sa_clear (index_t sai)
{
  vlib_zero_combined_counter (&ipsec_sa_counters, sai);
}

void
ipsec_sa_walk (ipsec_sa_walk_cb_t cb, void *ctx)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;

  /* *INDENT-OFF* */
  pool_foreach (sa, im->sad,
  ({
    if (WALK_CONTINUE != cb(sa, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
ipsec_sa_fib_node_get (fib_node_index_t index)
{
  ipsec_main_t *im;
  ipsec_sa_t *sa;

  im = &ipsec_main;
  sa = pool_elt_at_index (im->sad, index);

  return (&sa->node);
}

static ipsec_sa_t *
ipsec_sa_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_IPSEC_SA == node->fn_type);
  return ((ipsec_sa_t *) (((char *) node) -
			  STRUCT_OFFSET_OF (ipsec_sa_t, node)));

}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
ipsec_sa_last_lock_gone (fib_node_t * node)
{
  /*
   * The ipsec SA is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ipsec_sa_del (ipsec_sa_from_fib_node (node));
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
ipsec_sa_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  ipsec_sa_stack (ipsec_sa_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * Virtual function table registered by SAs
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t ipsec_sa_vft = {
  .fnv_get = ipsec_sa_fib_node_get,
  .fnv_last_lock = ipsec_sa_last_lock_gone,
  .fnv_back_walk = ipsec_sa_back_walk,
};

/* force inclusion from application's main.c */
clib_error_t *
ipsec_sa_interface_init (vlib_main_t * vm)
{
  fib_node_register_type (FIB_NODE_TYPE_IPSEC_SA, &ipsec_sa_vft);

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_sa_interface_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

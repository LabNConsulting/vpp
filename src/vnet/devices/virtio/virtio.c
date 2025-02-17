/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

virtio_main_t virtio_main;

#define _IOCTL(fd,a,...) \
  if (ioctl (fd, a, __VA_ARGS__) < 0) \
    { \
      err = clib_error_return_unix (0, "ioctl(" #a ")"); \
      goto error; \
    }

static clib_error_t *
call_read_ready (clib_file_t * uf)
{
  virtio_main_t *nm = &virtio_main;
  vnet_main_t *vnm = vnet_get_main ();
  u16 qid = uf->private_data & 0xFFFF;
  virtio_if_t *vif =
    vec_elt_at_index (nm->interfaces, uf->private_data >> 16);
  u64 b;

  CLIB_UNUSED (ssize_t size) = read (uf->file_descriptor, &b, sizeof (b));
  if ((qid & 1) == 0)
    vnet_device_input_set_interrupt_pending (vnm, vif->hw_if_index,
					     RX_QUEUE_ACCESS (qid));

  return 0;
}


clib_error_t *
virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx, u16 sz)
{
  virtio_vring_t *vring;
  clib_file_t t = { 0 };
  int i;

  if (!is_pow2 (sz))
    return clib_error_return (0, "ring size must be power of 2");

  if (sz > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (sz == 0)
    sz = 256;

  if (idx % 2)
    {
      vlib_thread_main_t *thm = vlib_get_thread_main ();
      vec_validate_aligned (vif->txq_vrings, TX_QUEUE_ACCESS (idx),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (idx));
      if (thm->n_vlib_mains > vif->num_txqs)
	clib_spinlock_init (&vring->lockp);
    }
  else
    {
      vec_validate_aligned (vif->rxq_vrings, RX_QUEUE_ACCESS (idx),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (idx));
    }
  i = sizeof (vring_desc_t) * sz;
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->desc = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->desc, 0, i);

  i = sizeof (vring_avail_t) + sz * sizeof (vring->avail->ring[0]);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->avail = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->avail, 0, i);
  // tell kernel that we don't need interrupt
  vring->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  i = sizeof (vring_used_t) + sz * sizeof (vring_used_elem_t);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->used, 0, i);

  vring->queue_id = idx;
  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, sz, CLIB_CACHE_LINE_BYTES);

  if (idx & 1)
    {
      clib_memset_u32 (vring->buffers, ~0, sz);
    }

  vring->size = sz;
  vring->call_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  vring->kick_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  virtio_log_debug (vif, "vring %u size %u call_fd %d kick_fd %d", idx,
		    vring->size, vring->call_fd, vring->kick_fd);

  t.read_function = call_read_ready;
  t.file_descriptor = vring->call_fd;
  t.private_data = vif->dev_instance << 16 | idx;
  t.description = format (0, "%U vring %u", format_virtio_device_name,
			  vif->dev_instance, idx);
  vring->call_file_index = clib_file_add (&file_main, &t);

  return 0;
}

inline void
virtio_free_rx_buffers (vlib_main_t * vm, virtio_vring_t * vring)
{
  u16 used = vring->desc_in_use;
  u16 last = vring->last_used_idx;
  u16 mask = vring->size - 1;

  while (used)
    {
      vlib_buffer_free (vm, &vring->buffers[last & mask], 1);
      last++;
      used--;
    }
}

clib_error_t *
virtio_vring_free_rx (vlib_main_t * vm, virtio_if_t * vif, u32 idx)
{
  virtio_vring_t *vring =
    vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (idx));

  clib_file_del_by_index (&file_main, vring->call_file_index);
  close (vring->kick_fd);
  close (vring->call_fd);
  if (vring->used)
    {
      virtio_free_rx_buffers (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  return 0;
}

inline void
virtio_free_used_desc (vlib_main_t * vm, virtio_vring_t * vring)
{
  u16 used = vring->desc_in_use;
  u16 sz = vring->size;
  u16 mask = sz - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = vring->used->idx - last;

  if (n_left == 0)
    return;

  while (n_left)
    {
      vring_used_elem_t *e = &vring->used->ring[last & mask];
      u16 slot = e->id;

      vlib_buffer_free (vm, &vring->buffers[slot], 1);
      used--;
      last++;
      n_left--;
    }
  vring->desc_in_use = used;
  vring->last_used_idx = last;
}

clib_error_t *
virtio_vring_free_tx (vlib_main_t * vm, virtio_if_t * vif, u32 idx)
{
  virtio_vring_t *vring =
    vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (idx));

  clib_file_del_by_index (&file_main, vring->call_file_index);
  close (vring->kick_fd);
  close (vring->call_fd);
  if (vring->used)
    {
      virtio_free_used_desc (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  gro_flow_table_free (vring->flow_table);
  clib_spinlock_free (&vring->lockp);
  return 0;
}

void
virtio_set_packet_coalesce (virtio_if_t * vif)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  virtio_vring_t *vring;
  vif->packet_coalesce = 1;
  vec_foreach (vring, vif->txq_vrings)
  {
    gro_flow_table_init (&vring->flow_table,
			 vif->type & (VIRTIO_IF_TYPE_TAP |
				      VIRTIO_IF_TYPE_PCI), hw->tx_node_index);
  }
}

void
virtio_vring_set_numa_node (vlib_main_t * vm, virtio_if_t * vif, u32 idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thread_index;
  virtio_vring_t *vring =
    vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (idx));
  thread_index =
    vnet_get_device_input_thread_index (vnm, vif->hw_if_index,
					RX_QUEUE_ACCESS (idx));
  vring->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm,
					   vlib_mains
					   [thread_index]->numa_node);
}

inline void
virtio_set_net_hdr_size (virtio_if_t * vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF) ||
      vif->features & VIRTIO_FEATURE (VIRTIO_F_VERSION_1))
    vif->virtio_net_hdr_sz = sizeof (virtio_net_hdr_v1_t);
  else
    vif->virtio_net_hdr_sz = sizeof (virtio_net_hdr_t);
}

inline void
virtio_show (vlib_main_t * vm, u32 * hw_if_indices, u8 show_descr, u32 type)
{
  u32 i, j, hw_if_index;
  virtio_if_t *vif;
  vnet_main_t *vnm = &vnet_main;
  virtio_main_t *mm = &virtio_main;
  virtio_vring_t *vring;
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(s,b) { .str = #s, .bit = b, },
    foreach_virtio_net_features
#undef _
    {.str = NULL}
  };

  struct feat_struct *flag_entry;
  static struct feat_struct flags_array[] = {
#define _(b,e,s) { .bit = b, .str = s, },
    foreach_virtio_if_flag
#undef _
    {.str = NULL}
  };

  if (!hw_if_indices)
    return;

  for (hw_if_index = 0; hw_if_index < vec_len (hw_if_indices); hw_if_index++)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (vnm, hw_if_indices[hw_if_index]);
      vif = pool_elt_at_index (mm->interfaces, hi->dev_instance);
      if (vif->type != type)
	continue;
      vlib_cli_output (vm, "Interface: %U (ifindex %d)",
		       format_vnet_hw_if_index_name, vnm,
		       hw_if_indices[hw_if_index], vif->hw_if_index);
      if (type == VIRTIO_IF_TYPE_PCI)
	{
	  vlib_cli_output (vm, "  PCI Address: %U", format_vlib_pci_addr,
			   &vif->pci_addr);
	}
      if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	{
	  u8 *str = 0;
	  if (vif->host_if_name)
	    vlib_cli_output (vm, "  name \"%s\"", vif->host_if_name);
	  if (vif->net_ns)
	    vlib_cli_output (vm, "  host-ns \"%s\"", vif->net_ns);
	  if (vif->host_mtu_size)
	    vlib_cli_output (vm, "  host-mtu-size \"%d\"",
			     vif->host_mtu_size);
	  if (type == VIRTIO_IF_TYPE_TAP)
	    vlib_cli_output (vm, "  host-mac-addr: %U",
			     format_ethernet_address, vif->host_mac_addr);

	  vec_foreach_index (i, vif->vhost_fds)
	    str = format (str, " %d", vif->vhost_fds[i]);
	  vlib_cli_output (vm, "  vhost-fds%v", str);
	  vec_free (str);
	  vec_foreach_index (i, vif->tap_fds)
	    str = format (str, " %d", vif->tap_fds[i]);
	  vlib_cli_output (vm, "  tap-fds%v", str);
	  vec_free (str);
	}
      vlib_cli_output (vm, "  gso-enabled %d", vif->gso_enabled);
      vlib_cli_output (vm, "  csum-enabled %d", vif->csum_offload_enabled);
      vlib_cli_output (vm, "  packet-coalesce %d", vif->packet_coalesce);
      if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_PCI))
	vlib_cli_output (vm, "  Mac Address: %U", format_ethernet_address,
			 vif->mac_addr);
      vlib_cli_output (vm, "  Device instance: %u", vif->dev_instance);
      vlib_cli_output (vm, "  flags 0x%x", vif->flags);
      flag_entry = (struct feat_struct *) &flags_array;
      while (flag_entry->str)
	{
	  if (vif->flags & (1ULL << flag_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", flag_entry->str,
			     flag_entry->bit);
	  flag_entry++;
	}
      if (type == VIRTIO_IF_TYPE_PCI)
	{
	  device_status (vm, vif);
	}
      vlib_cli_output (vm, "  features 0x%lx", vif->features);
      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vif->features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}
      vlib_cli_output (vm, "  remote-features 0x%lx", vif->remote_features);
      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vif->remote_features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}
      vlib_cli_output (vm, "  Number of RX Virtqueue  %u", vif->num_rxqs);
      vlib_cli_output (vm, "  Number of TX Virtqueue  %u", vif->num_txqs);
      if (vif->cxq_vring != NULL
	  && vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
	vlib_cli_output (vm, "  Number of CTRL Virtqueue 1");
      vec_foreach_index (i, vif->rxq_vrings)
      {
	vring = vec_elt_at_index (vif->rxq_vrings, i);
	vlib_cli_output (vm, "  Virtqueue (RX) %d", vring->queue_id);
	vlib_cli_output (vm,
			 "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			 vring->size, vring->last_used_idx, vring->desc_next,
			 vring->desc_in_use);
	vlib_cli_output (vm,
			 "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			 vring->avail->flags, vring->avail->idx,
			 vring->used->flags, vring->used->idx);
	if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	  {
	    vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			     vring->call_fd);
	  }
	if (show_descr)
	  {
	    vlib_cli_output (vm, "\n  descriptor table:\n");
	    vlib_cli_output (vm,
			     "   id          addr         len  flags  next      user_addr\n");
	    vlib_cli_output (vm,
			     "  ===== ================== ===== ====== ===== ==================\n");
	    for (j = 0; j < vring->size; j++)
	      {
		vring_desc_t *desc = &vring->desc[j];
		vlib_cli_output (vm,
				 "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				 j, desc->addr,
				 desc->len,
				 desc->flags, desc->next, desc->addr);
	      }
	  }
      }
      vec_foreach_index (i, vif->txq_vrings)
      {
	vring = vec_elt_at_index (vif->txq_vrings, i);
	vlib_cli_output (vm, "  Virtqueue (TX) %d", vring->queue_id);
	vlib_cli_output (vm,
			 "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			 vring->size, vring->last_used_idx, vring->desc_next,
			 vring->desc_in_use);
	vlib_cli_output (vm,
			 "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			 vring->avail->flags, vring->avail->idx,
			 vring->used->flags, vring->used->idx);
	if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	  {
	    vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			     vring->call_fd);
	  }
	if (vring->flow_table)
	  {
	    vlib_cli_output (vm, "    %U", gro_flow_table_format,
			     vring->flow_table);
	  }
	if (show_descr)
	  {
	    vlib_cli_output (vm, "\n  descriptor table:\n");
	    vlib_cli_output (vm,
			     "   id          addr         len  flags  next      user_addr\n");
	    vlib_cli_output (vm,
			     "  ===== ================== ===== ====== ===== ==================\n");
	    for (j = 0; j < vring->size; j++)
	      {
		vring_desc_t *desc = &vring->desc[j];
		vlib_cli_output (vm,
				 "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				 j, desc->addr,
				 desc->len,
				 desc->flags, desc->next, desc->addr);
	      }
	  }
      }
      if (vif->cxq_vring != NULL
	  && vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
	{
	  vring = vif->cxq_vring;
	  vlib_cli_output (vm, "  Virtqueue (CTRL) %d", vring->queue_id);
	  vlib_cli_output (vm,
			   "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			   vring->size, vring->last_used_idx,
			   vring->desc_next, vring->desc_in_use);
	  vlib_cli_output (vm,
			   "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			   vring->avail->flags, vring->avail->idx,
			   vring->used->flags, vring->used->idx);
	  if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	    {
	      vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			       vring->call_fd);
	    }
	  if (show_descr)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm,
			       "   id          addr         len  flags  next      user_addr\n");
	      vlib_cli_output (vm,
			       "  ===== ================== ===== ====== ===== ==================\n");
	      for (j = 0; j < vring->size; j++)
		{
		  vring_desc_t *desc = &vring->desc[j];
		  vlib_cli_output (vm,
				   "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				   j, desc->addr,
				   desc->len,
				   desc->flags, desc->next, desc->addr);
		}
	    }
	}

    }

}

static clib_error_t *
virtio_init (vlib_main_t * vm)
{
  virtio_main_t *vim = &virtio_main;
  clib_error_t *error = 0;

  vim->log_default = vlib_log_register_class ("virtio", 0);
  vlib_log_debug (vim->log_default, "initialized");

  return error;
}

VLIB_INIT_FUNCTION (virtio_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * January 10 2020, Christian E. Hopps <chopps@labn.net>
 *
 * Copyright (c) 2020, LabN Consulting, L.L.C
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_iptfs_msg_enum_h
#define included_iptfs_msg_enum_h

#include <vppinfra/byte_order.h>

#define vl_msg_id(n, h) n,
typedef enum
{
#include <iptfs/iptfs_all_api_h.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

#endif /* included_iptfs_msg_enum_h */

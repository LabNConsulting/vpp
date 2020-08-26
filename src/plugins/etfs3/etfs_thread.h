/*
 * Copyright (c) 2020, LabN Consulting, L.L.C
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
#ifndef included_etfs_thread_h
#define included_etfs_thread_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>
#include <stdatomic.h>

#include <plugins/etfs3/etfs3.h>

/*
 * Might need to move these to etfs3.h
 */
extern vlib_node_registration_t	etfs_encap_pacer_node;
extern vlib_node_registration_t	etfs_zpool_poll_node;
extern vlib_node_registration_t	etfs_output_node;
extern vlib_node_registration_t	etfs_decap_processor_node;

#define foreach_etfs_encap_polling_node_type		\
    _(ETFS_ENCAP_POLLER_PACER)				\
    _(ETFS_ENCAP_POLLER_ZPOOL)				\
    _(ETFS_ENCAP_POLLER_OUTPUT)

typedef enum
{
#define _(E) E,
    foreach_etfs_encap_polling_node_type
#undef _
    ETFS_ENCAP_POLLER_COUNT,
} etfs_encap_polling_node_type_t;

#define foreach_etfs_decap_polling_node_type		\
    _(ETFS_DECAP_POLLER_PROCESSOR)

typedef enum
{
#define _(E) E,
    foreach_etfs_decap_polling_node_type
#undef _
    ETFS_DECAP_POLLER_COUNT,
} etfs_decap_polling_node_type_t;

/* forward */
struct state_encap_flow_v2;
struct state_decap_flow_v2;

typedef struct
{
    u32				thread_index;
    /*
     * Array of per-etfs-thread-type vectors.
     * Each vector has an element per flow; is indexed by flow index
     */
    struct state_encap_flow_v2	**flows[ETFS_ENCAP_POLLER_COUNT];
    struct state_decap_flow_v2	**flows_decap[ETFS_DECAP_POLLER_COUNT];

} etfs_thread_main_t;

extern u32
etfs_encap_node_index(etfs_encap_polling_node_type_t nodetype);

extern u32
etfs_thread_encap_place(
    struct state_encap_flow_v2	*ef,
    u32				*output_thread_index);	/* NULL = auto */

extern void
etfs_thread_decap_place(
    struct state_decap_flow_v2	*df);

extern void
etfs_thread_encap_unplace(struct state_encap_flow_v2 *ef);

extern void
etfs_thread_decap_unplace(struct state_decap_flow_v2 *df);

#ifdef __cplusplus
}
#endif

#endif /* included_etfs_thread_h */

/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

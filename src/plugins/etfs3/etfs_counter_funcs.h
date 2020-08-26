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

/*
 * THIS FILE IS MEANT TO BE INCLUDED BY etfs3.h, NOT BY INDIVIDUAL C FILES
 */

#ifndef included_etfs_counter_funcs_h
#define included_etfs_counter_funcs_h

#ifdef __cplusplus
extern "C" {
#endif

static inline void
etfs_global_sctr_add(etfs_global_sctr_t ctr, u64 count)
{
    vlib_increment_simple_counter(
	&etfs3_main.global_scm[ctr], vlib_get_main()->thread_index,
	0, count);
}

static inline void
etfs_encap_sctr_inc(etfs_encap_sctr_t ctr, u16 flow_index)
{
    vlib_increment_simple_counter(
	&etfs3_main.encap_scm[ctr], vlib_get_main()->thread_index,
	flow_index, 1);
}

static inline void
etfs_encap_sctr_add(etfs_encap_sctr_t ctr, u16 flow_index, u64 count)
{
    vlib_increment_simple_counter(
	&etfs3_main.encap_scm[ctr], vlib_get_main()->thread_index,
	flow_index, count);
}

static inline void
etfs_decap_sctr_inc(etfs_decap_sctr_t ctr, u16 flow_index)
{
    vlib_increment_simple_counter(
	&etfs3_main.decap_scm[ctr], vlib_get_main()->thread_index,
	flow_index, 1);
}

static inline void
etfs_decap_sctr_add(etfs_decap_sctr_t ctr, u16 flow_index, u64 count)
{
    vlib_increment_simple_counter(
	&etfs3_main.decap_scm[ctr], vlib_get_main()->thread_index,
	flow_index, count);
}

static inline void
etfs_encap_cctr_inc(etfs_encap_cctr_t ctr, u16 flow_index, u32 bytes)
{
    vlib_increment_combined_counter(
	&etfs3_main.encap_ccm[ctr], vlib_get_main()->thread_index,
	flow_index, 1, bytes);
}

static inline void
etfs_encap_cctr_add(etfs_encap_cctr_t ctr, u16 flow_index, u64 count, u32 bytes)
{
    vlib_increment_combined_counter(
	&etfs3_main.encap_ccm[ctr], vlib_get_main()->thread_index,
	flow_index, count, bytes);
}

static inline void
etfs_decap_cctr_inc(etfs_decap_cctr_t ctr, u16 flow_index, u32 bytes)
{
    vlib_increment_combined_counter(
	&etfs3_main.decap_ccm[ctr], vlib_get_main()->thread_index,
	flow_index, 1, bytes);
}

static inline void
etfs_decap_cctr_add(etfs_decap_cctr_t ctr, u16 flow_index, u64 count, u32 bytes)
{
    vlib_increment_combined_counter(
	&etfs3_main.decap_ccm[ctr], vlib_get_main()->thread_index,
	flow_index, count, bytes);
}

static inline void
etfs_clear_counters(void)
{
    for (uint i = 0; i < ETFS_GLOBAL_SCTR_N_COUNTERS; ++i)
	vlib_clear_simple_counters(&etfs3_main.global_scm[i]);

    for (uint i = 0; i < ETFS_ENCAP_SCTR_N_COUNTERS; ++i)
	vlib_clear_simple_counters(&etfs3_main.encap_scm[i]);
    for (uint i = 0; i < ETFS_ENCAP_CCTR_N_COUNTERS; ++i)
	vlib_clear_combined_counters(&etfs3_main.encap_ccm[i]);

    for (uint i = 0; i < ETFS_DECAP_SCTR_N_COUNTERS; ++i)
	vlib_clear_simple_counters(&etfs3_main.decap_scm[i]);
    for (uint i = 0; i < ETFS_DECAP_CCTR_N_COUNTERS; ++i)
	vlib_clear_combined_counters(&etfs3_main.decap_ccm[i]);
}

#ifdef __cplusplus
}
#endif

#endif /* included_etfs_counter_funcs_h */

/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

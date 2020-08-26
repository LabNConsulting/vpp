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
#ifndef included_etfs_debug_h
#define included_etfs_debug_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <vlib/vlib.h>


/*
 * default debug levels
 */
/* flow add/delete */
#define ETFS_DEBUG_ENCAP_FLOW_LOGLEVEL		1
#define ETFS_DEBUG_DECAP_FLOW_LOGLEVEL		1
#define ETFS_DEBUG_THREAD_FLOW_SET_LOGLEVEL	3

/* encapsulator */
#define ETFS_DEBUG_ENCAP_TX_ONE_LOGLEVEL	0
#define ETFS_DEBUG_ENCAP_RX_LOGLEVEL		0
#define ETFS_DEBUG_ENCAP_TX_LOGLEVEL		0
#define ETFS_DEBUG_ENCAP_OUTPUT_LOGLEVEL	0
#define ETFS_DEBUG_ENCAP_INPROGRESS_LOGLEVEL	0
#define ETFS_DEBUG_ENCAP_SPLIT_LOGLEVEL		0
#define ETFS_DEBUG_ENCAP_FRAG_LOGLEVEL		0
#define ETFS_DEBUG_PACER_LOGLEVEL		0
#define ETFS_DEBUG_ZPOOL_LOGLEVEL		0
#define ETFS_DEBUG_OUTPUT_TRACE_LOGLEVEL	0

/* decapsulator */
#define ETFS_DEBUG_DECAP_LOGLEVEL		0
#define ETFS_DEBUG_DECAP_NOFLOW_LOGLEVEL	0
#define ETFS_DEBUG_DECAP_MALFORMED_LOGLEVEL	0
#define ETFS_DEBUG_DECAP_RX_TRACE_LOGLEVEL	0
#define ETFS_DEBUG_DECAP_TX_TRACE_LOGLEVEL	0

#define ETFS_DEBUG_REASM_RX_LOGLEVEL		0
#define ETFS_DEBUG_REASM_REASM_LOGLEVEL 	0

#define ETFS_DEBUG_190802_LOGLEVEL		0
#define ETFS_DEBUG_CONTROL_LOGLEVEL		1

/*
 * The conditional test is a constant expression, so the compiler ought to
 * optimize this code out as appropriate.
 */
#define ETFS_DEBUG(COMPONENT, LEVEL, ...)			\
    do {							\
	if ((LEVEL) <= ETFS_DEBUG_##COMPONENT##_LOGLEVEL) {	\
	    /*printf("%s|%d ", __func__, __LINE__);*//*mimic clib_warning*/\
	    /*printf(__VA_ARGS__);*/				\
	    clib_warning(__VA_ARGS__);				\
	}							\
    }	while (0)

/* "format" semantics */
#define ETFS_DEBUG_F(COMPONENT, LEVEL, ...)			\
    do {							\
	if ((LEVEL) <= ETFS_DEBUG_##COMPONENT##_LOGLEVEL) {	\
	    u8	*s;						\
	    s = format(0, __VA_ARGS__);				\
	    s = format(s, "%c", 0); /* NUL-terminate */		\
	    /*printf("%s|%d ", __func__, __LINE__);*//*mimic clib_warning*/\
	    /*printf("%s", s);*/					\
	    clib_warning("%s", s);				\
	    vec_free(s);					\
	}							\
    }	while (0)

#endif /* included_etfs_debug_h */

/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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

#ifndef included_etfs_counter_h
#define included_etfs_counter_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 * counter ID names:
 *
 *	ETFS_SCTR_[NODETYPE]_[COUNTER]
 *
 * COUNTER name components:
 *
 *	E/D (encap/decap)
 *	RX/TX
 *	PKT/BUF		packet in the wire vs. internal buffer (?)
 *	DROP/other
 *
 * Counters are per-flow.
 *
 * The naming slightly confounds the flow direction (encap/decap) with
 * the prefixes of the node names (encap_/decap_) but the etfs nodes
 * all belong to one or the other flow direction so this laxity is not
 * a problem. (See the construction of the counter enum names by the
 * ETFS_[EN|DE]CAP_[S|C]TR_INC() macros)
 */

#define foreach_etfs_global_simple_counter				\
    _(DECAP_RX,				"decap-rx")			\
    _(DECAP_RX_ALLPAD,			"decap-rx-all-pad")		\
    _(DECAP_DROP_NOFLOW,		"decap-drop-no-flow")

#define foreach_etfs_encap_simple_counter				\
    _(RX_ENCODE_TAILLESS,		"encode-frag-TAILLESS")		\
    _(RX_ENCODE_TF_SEQ,			"encode-tf-seq")		\
    									\
    _(OUT_POLL_DUE_HAVE_TF,		"out-poll-due-have-tf")		\
    _(OUT_POLL_DUE_NO_TF,		"out-poll-due-no-tf")		\
    _(OUT_TF_HELD_FSLIMIT,		"out-tf-held-fslimit")		\
    _(OUT_TF_DUE,			"out-tf-due")			\
    _(OUT_TF_SLIPS,			"out-tf-slips")			\
    _(OUT_TF_NOTSENT,			"out-tf-NOTSENT")		\
    									\
    _(PACER_POLL_DUE_HAVE_TF,		"pacer-poll-due-have-tf")	\
    _(PACER_POLL_DUE_NO_TF,		"pacer-poll-due-no-tf")		\
    _(PACER_POLL_DUE_SRING_NO_OPEN,	"pacer-poll-due-sring-no-open")	\
    _(PACER_POLL_MISSED,		"pacer-poll-missed")		\
    _(PACER_POLL_LIMITED_FRAME_SIZE,	"pacer-poll-lim-framesize")	\
    _(PACER_SRING_PUT_FAILURE,		"pacer-SRING-PUT-FAILURES")

#define foreach_etfs_decap_simple_counter				\
    _(RX_DROP_DDQ_FULL,			"drop-ddq-full")		\
    _(RX_DROP_SRING_PUT_FAIL,		"drop-SRING-PUT-FAIL")		\
    _(RX_FFC_COUNTED_TOTAL,		"ffc-counted-total")		\
    _(RX_FFC_OK,			"ffc-ok")			\
    _(RX_FFC_MISMATCH,			"FFC-MISMATCH")			\
    _(RX_TF_SEQ_OK,			"tf-seq-ok")			\
    _(RX_TF_SEQ_MISMATCH,		"TF-SEQ-MISMATCH")		\
    _(FRAG_SEQ_EXPECTED,		"frag-seq-expected")		\
    _(FRAG_SEQ_OLD_DROP,		"frag-seq-old-drop")		\
    _(FRAG_SEQ_IN_WIN,			"frag-seq-in-win")		\
    _(FRAG_SEQ_IN_WIN_DUP_DROP,		"frag-seq-in-win-dup-drop")	\
    _(FRAG_SEQ_BEYOND_WIN,		"frag-seq-beyond-win")		\
									\
    _(FRAG_DEQUEUED_DROP_SHIFT1,	"frag-dequeued-drop-shift-1")	\
    _(FRAG_DEQUEUED_DROP_SHIFT2,	"frag-dequeued-drop-shift-2")	\
    _(FRAG_DEQUEUED_DROP_NOTHOL,	"frag-dequeued-drop-nothol")	\
    _(FRAG_DEQUEUED_DROP_TAILLESS,	"frag-dequeued-drop-TAILLESS")	\
    									\
    _(TX_COMPACT_FAILED,		"tx-compact-failed")

#define foreach_etfs_encap_combined_counter				\
    _(RX_ENCODE_PKT_RX,			"encode-pkt-rx")		\
    _(RX_ENCODE_PKT_DROP_QFULL,		"encode-pkt-drop-qfull")	\
    _(RX_ENCODE_PKT_DROP_NOBUFS,	"encode-pkt-drop-nobufs")	\
    _(RX_ENCODE_PKT_TRUNCATE_NOBUFS,	"encode-pkt-truncate-nobufs")	\
    _(RX_ENCODE_PKT_ENQUEUED_FULL,	"encode-pkt-enqueued-full")	\
    _(RX_ENCODE_PKT_ENQUEUED_FRAGMENTED, "encode-pkt-enqueued-fragmented")\
    _(RX_ENCODE_FRAG_ENQUEUED,		"encode-frag-enqueued")		\
    _(RX_ENCODE_TF_DROP_COMPACT,	"encode-tf-drop-compact")	\
    _(RX_ENCODE_TF_DROP_QSLOTS,		"encode-tf-drop-qslots")	\
    _(RX_ENCODE_TF_ENQUEUED,		"encode-tf-out-enqueued")	\
    _(RX_ENCODE_TF_PLUCKED,		"encode-tf-out-plucked")	\
									\
    _(PACER_TF_DEQUEUED,		"pacer-tf-in-dequeued")		\
    _(PACER_TF_PLUCKED,			"pacer-tf-in-plucked")		\
    _(PACER_TF_DROP_QSLOTS,		"pacer-tf-DROP-QSLOTS")		\
    _(PACER_TF_DROP_COMPACT,		"pacer-tf-drop-compact")	\
    _(PACER_TF_ENQUEUED,		"pacer-tf-out-enqueued")	\
    _(PACER_QSLOTS_SHRANK,		"pacer-qslots-shrank")		\
    _(PACER_SRING_PUT_FAIL,		"pacer-SRING-PUT-FAIL")		\
    									\
    _(OUT_TF_SENT_UF,			"out-tf-sent-uf")		\
    _(OUT_TF_SENT_ALLPAD,		"out-tf-sent-allpad")		\
    _(OUT_TF_SENT_ALLPAD_FAKE,		"out-tf-sent-allpad-fake")	\
    _(OUT_TF_SENT_TOTAL,		"out-tf-sent-total")		\
    _(OUT_TF_UNDERRUN_ALLPAD,		"out-underrun-allpad")

#if ETFS_VERIFY_TRAILING_PAD
 #define _ETFS_CTR_NZP _(RX_TF_NONZERO_PAD, "tf-nonzero-pad")
#else
 #define _ETFS_CTR_NZP
#endif

#define foreach_etfs_decap_combined_counter				\
    _(RX_TF_RX,				"tf-rx")			\
    _(RX_TF_RX_UF,			"tf-rx-uf")			\
    _(RX_TF_RX_UNKNOWN,			"tf-rx-unknown")		\
    _(RX_TF_RX_EPAD_ONLY,		"tf-rx-epad-only")		\
    _(RX_TF_RX_ALL_PAD,			"tf-rx-all-pad")		\
    									\
    _(RX_TF_DROP_MALF_SET0,		"tf-drop-malformed-set0")	\
    _(RX_TF_DROP_MALF_CTFL,		"tf-drop-malformed-CTFL")	\
    _(RX_TF_DROP_MALF_CTFL_ADV,		"tf-drop-malformed-ctfl-adv")	\
    _(RX_TF_DROP_MALF_FRAG_GETSEQ,	"tf-drop-malformed-frag-getseq")\
    _(RX_TF_DROP_MALF_FRAG_GETSEQ_ADV,	"tf-drop-malformed-frag-getseq-adv")\
    _(RX_TF_DROP_FRAMING,		"tf-drop-framing")		\
    _(RX_TF_DROP_FRAMING_ADV,		"tf-drop-framing-adv")		\
    									\
    _ETFS_CTR_NZP							\
    									\
    _(RX_C_FULL,			"rx-c-full")			\
    _(RX_C_FRAG,			"rx-c-frag")			\
    _(RX_C_UNKNOWN,			"rx-comp-unknown")		\
    									\
    _(DECODE_FULL_SENT,			"decode-full-sent")		\
    _(DECODE_FULL_DROP_CLONE,		"decode-full-drop-clone")	\
    _(DECODE_FRAG_QUEUED,		"decode-frag-queued")		\
    _(DECODE_FRAG_DROP_CLONE,		"decode-frag-drop-clone")	\
    _(DECODE_DROP_NOBUFS,		"decode-drop-nobufs")		\
    _(DECODE_PKT_SENT_TOTAL,		"decode-pkt-sent-total")	\
    									\
    _(FRAG_DEQUEUED_ASSEMBLED,		"frag-dequeued-assembled")	\
    _(FRAG_DEQUEUED_DROP_ASM_NOMEM,	"frag-dequeued-drop-asm-nomem")	\
    _(FRAG_PKT_DROP_ASM_NOMEM,		"pkt-drop-asm-nomem")		\
    _(FRAG_PKT_SENT_ASM,		"pkt-sent-asm")



typedef enum {
#define _(E, n) ETFS_GLOBAL_SCTR_##E,
    foreach_etfs_global_simple_counter
#undef _
    ETFS_GLOBAL_SCTR_N_COUNTERS
} etfs_global_sctr_t;

typedef enum {
#define _(E, n) ETFS_ENCAP_SCTR_##E,
    foreach_etfs_encap_simple_counter
#undef _
    ETFS_ENCAP_SCTR_N_COUNTERS
} etfs_encap_sctr_t;

typedef enum {
#define _(E, n) ETFS_DECAP_SCTR_##E,
    foreach_etfs_decap_simple_counter
#undef _
    ETFS_DECAP_SCTR_N_COUNTERS
} etfs_decap_sctr_t;

typedef enum {
#define _(E, n) ETFS_ENCAP_CCTR_##E,
    foreach_etfs_encap_combined_counter
#undef _
    ETFS_ENCAP_CCTR_N_COUNTERS
} etfs_encap_cctr_t;

typedef enum {
#define _(E, n) ETFS_DECAP_CCTR_##E,
    foreach_etfs_decap_combined_counter
#undef _
    ETFS_DECAP_CCTR_N_COUNTERS
} etfs_decap_cctr_t;

/*
 * TBD make all of the C functions *_add and encode the "1" here
 */

#define ETFS_GLOBAL_SCTR_INC(COUNTER) \
    etfs_global_sctr_add(ETFS_GLOBAL_SCTR_##COUNTER, 1)

#define ETFS_GLOBAL_SCTR_ADD(COUNTER, COUNT) \
    etfs_global_sctr_add(ETFS_GLOBAL_SCTR_##COUNTER, COUNT)

#define ETFS_ENCAP_SCTR_INC(NODETYPE, COUNTER, FLOW) \
    etfs_encap_sctr_inc(ETFS_ENCAP_SCTR_##NODETYPE##_##COUNTER, FLOW)

#define ETFS_ENCAP_SCTR_ADD(NODETYPE, COUNTER, FLOW, COUNT) \
    etfs_encap_sctr_add(ETFS_ENCAP_SCTR_##NODETYPE##_##COUNTER, FLOW, COUNT)

#define ETFS_DECAP_SCTR_INC(NODETYPE, COUNTER, FLOW) \
    etfs_decap_sctr_inc(ETFS_DECAP_SCTR_##NODETYPE##_##COUNTER, FLOW)

#define ETFS_DECAP_SCTR_ADD(NODETYPE, COUNTER, FLOW, COUNT) \
    etfs_decap_sctr_add(ETFS_DECAP_SCTR_##NODETYPE##_##COUNTER, FLOW, COUNT)

#define ETFS_ENCAP_CCTR_INC(NODETYPE, COUNTER, FLOW, BYTES)	\
    etfs_encap_cctr_inc(ETFS_ENCAP_CCTR_##NODETYPE##_##COUNTER, FLOW, BYTES)

#define ETFS_ENCAP_CCTR_ADD(NODETYPE, COUNTER, FLOW, COUNT, BYTES)	\
    etfs_encap_cctr_add(ETFS_ENCAP_CCTR_##NODETYPE##_##COUNTER, FLOW, COUNT, BYTES)

#define ETFS_DECAP_CCTR_INC(NODETYPE, COUNTER, FLOW, BYTES)	\
    etfs_decap_cctr_inc(ETFS_DECAP_CCTR_##NODETYPE##_##COUNTER, FLOW, BYTES)

#define ETFS_DECAP_CCTR_ADD(NODETYPE, COUNTER, FLOW, COUNT, BYTES)	\
    etfs_decap_cctr_add(ETFS_DECAP_CCTR_##NODETYPE##_##COUNTER, FLOW, COUNT, BYTES)


#ifdef __cplusplus
}
#endif

#endif /* included_etfs_counter_h */

/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

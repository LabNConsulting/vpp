/*
 * March 2 2020, Christian E. Hopps <chopps@labn.net>
 *
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
#include <vppinfra/time.h>

typedef void (*deferred_callback_t) (void *data);

typedef struct deferred
{
  deferred_callback_t callback;
  void *data;
  f64 end;
} deferred_t;

#define foreach_deferred_event_type            \
  _ (DEFERRED_EVENT_TYPE_BOGUS, "bogus-event") \
  _ (DEFERRED_EVENT_TYPE_SCHEDULE, "schedule")

typedef enum
{
#define _(n, s) n,
  foreach_deferred_event_type
#undef _
      DEFERRED_EVENT_N_TYPES
} deferred_event_type_t;

extern char *deferred_event_type_strings[DEFERRED_EVENT_N_TYPES];

extern vlib_node_registration_t deferred_process_node;

static inline void
defer (vlib_main_t *vm, deferred_callback_t callback, void *data, f64 delay)
{
  deferred_t *deferred = vec_new (deferred_t, 1);
  deferred->callback = callback;
  deferred->data = data;
  deferred->end = vlib_time_now (vm) + delay;
  clib_warning ("%s: Signalling deferred process: 0x%wx", __FUNCTION__,
		(uword)deferred);
  vlib_process_signal_event_mt (vm, deferred_process_node.index,
				DEFERRED_EVENT_TYPE_SCHEDULE, (uword)deferred);
}

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "gnu"
 * End:
 */

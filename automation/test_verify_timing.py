# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# Copyright (c) 2020 LabN Consulting, L.L.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import logging

from autovpp import testlib
from autovpp import trexlib
from trex_stl_lib.api import STLClient


async def run_test(args, trex, vpplist):  # pylint: disable=R0914
    if not trex:
        c = None
    else:
        c = STLClient(server=trex.connect_host, sync_timeout=10, async_timeout=10)
        c.connect()

    if args.user_packet_size:
        imix_table = [{
            'size': args.user_packet_size,
            'pps': 1,
            'pg_id': 1,
        }]
        if args.impulses:
            imix_table[0]['impulses'] = args.impulses
            imix_table[0]['duration'] = args.duration
        func = trexlib.get_static_streams_seqnum
    else:
        assert not args.impulses
        imix_table = [{
            'size': 40,
            'pps': 28,
            'isg': 0,
        }, {
            'size': 576,
            'pps': 16,
            'isg': 0.1,
            'pg_id': 1,
        }, {
            'size': 1500,
            'pps': 4,
            'isg': 0.2,
        }]
        func = trexlib.get_static_streams

    # XXX may need to pass normalize option here??
    pps, avg_ipsize, _ = testlib.update_table_with_rate(args, imix_table, args.rate,
                                                        args.iptfs_packet_size, args.percentage)
    # Adjust PPS so we can pass "1" pps below.
    for x in imix_table:
        x["pps"] *= pps

    desc = f"Imix (avg: {avg_ipsize}) @ {pps}pps for {args.duration}s"
    logging.info("Running %s", desc)

    trex_stats, vstats, _ = await testlib.run_trex_cont_test(args,
                                                             c,
                                                             vpplist,
                                                             1,
                                                             func,
                                                             imix_table=imix_table,
                                                             extended_stats=True)

    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

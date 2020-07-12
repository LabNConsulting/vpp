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
import sys

from autovpp import testlib
from autovpp import trexlib
from trex_stl_lib.api import STLClient


async def run_test(args, trex, vpplist):  # pylint: disable=R0914
    if not trex:
        c = None
    else:
        c = STLClient(server=trex.connect_host, sync_timeout=10, async_timeout=10)
        c.connect()

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

    def mps(x):
        return 46 if x < 46 else x

    pps_sum = sum([x["pps"] for x in imix_table])
    avg_ipsize = sum([mps(x["size"]) * x["pps"] for x in imix_table]) / pps_sum
    pps = testlib.line_rate_to_iptfs_encap_pps(args.rate, avg_ipsize, args.iptfs_packet_size)
    if args.percentage:
        pps *= args.percentage / 100

    # Adjust the actual PPS to account for non-1 pps values in imix table
    for x in imix_table:
        x["pps"] *= pps / pps_sum

    desc = f"Imix (avg: {avg_ipsize}) @ {pps}pps for {args.duration}s"
    logging.info("Running %s", desc)

    def get_streams(direction, imix_table, modeclass=None, statsclass=None):
        return trexlib.get_static_streams(direction,
                                          imix_table,
                                          modeclass,
                                          statsclass,
                                          nstreams=args.connections)

    trex_stats, vstats, _ = await testlib.run_trex_cont_test(
        args,
        c,
        vpplist,
        1,
        get_streams,
        imix_table=imix_table,
        #extended_stats=True)
    )
    c.disconnect()
    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

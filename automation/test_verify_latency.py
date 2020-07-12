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
        c = STLClient(server=trex.connect_host)
        c.connect()

    ipsize = args.user_packet_size if args.user_packet_size else 576
    pps = testlib.line_rate_to_pps(args, args.rate, ipsize, args.iptfs_packet_size)
    if args.percentage:
        pps = pps * (args.percentage / 100)
    desc = f"Static IP Packet Size: {ipsize} @ {pps}pps for {args.duration}s"
    logging.info("Running %s", desc)

    def beatfunc(beatsecs):
        rx_miss = []
        for vppi, vpp in enumerate(vpplist):
            vpp.update_interface_counters()
            rx_miss_i = []
            for i in vpp.intf_stat_counters_i:
                rx_miss_i.append(vpp.intf_stat_counters_i[i]["/if/rx-miss"])
            rx_miss.append((vppi, rx_miss_i))
        logging.debug("%s", f"  BEAT INFO {beatsecs}: {rx_miss}")

    try:
        trex_stats, vstats, _ = await testlib.run_trex_cont_test(
            args,
            c,
            vpplist,
            1,
            #trexlib.get_static_streams_seqnum,
            trexlib.get_static_streams,
            imix_table=[{
                'size': ipsize,
                'pps': pps,
                'pg_id': 1,
            }],
            extended_stats=False,
            beat_callback=beatfunc,
            # beat_time=2,
            # statsclass=STLFlowLatencyStats)
        )

    except Exception as ex:
        print("Got exception: " + str(ex))
    finally:
        if c:
            c.disconnect()

    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

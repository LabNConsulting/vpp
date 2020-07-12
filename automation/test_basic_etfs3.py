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


#
# This test shows:
# A: Testing different size IP packets streams
# B: Testing at a given rate of PPS
# C: Testing with a static (or dynamic if changed) sized packet stream
# D: Specifying the packet size (or burst size if changed).
#
async def run_test(args, trex, vpplist):  # pylint: disable=R0914
    if not trex:
        c = None
    else:
        c = STLClient(server=trex.connect_host)
        c.connect()

    duration = float(args.duration) if args.duration is not None else 10

    # A: List of packets sizes to test.
    if args.user_packet_size:
        ipsizes = [args.user_packet_size]
    else:
        ipsizes = [46, 128, 256, 512, 576, 768, 1000, 1470, 1500, 4500, 9000]

    for ipsize in ipsizes:

        # B: Set the rate of packets to send.
        pps = testlib.line_rate_to_etfs_encap_pps(args.rate, ipsize, args.iptfs_packet_size,
                                                  not args.null)
        if args.percentage and args.percentage != 100:
            pps = pps * (args.percentage / 100)

        desc = f"Static IP Packet Size: {ipsize} @ {pps}pps for {duration}s, Tunnel Payload Size: {args.iptfs_packet_size}"
        logging.info("Running %s", desc)

        imix_table = [{
            'size': ipsize,
            'pps': 1,
        }]

        def get_streams(direction, imix_table, modeclass=None, statsclass=None, nstreams=1, ipv6=None):
            if (nstreams > 1):
                vlan_per_stream = True
            else:
                vlan_per_stream = False
            return trexlib.get_static_streams(direction,
                                              imix_table,
                                              modeclass,
                                              statsclass,
                                              nstreams=nstreams,
                                              vlan_per_stream=vlan_per_stream)

        trex_stats, vstats, _ = await testlib.run_trex_cont_test(
            args,
            c,
            vpplist,
            pps,
            # C: The function that defines the streams.
            get_streams,
            # D: The deifnition of the static packets for the streams.
            imix_table,
            # Enabling ext stats this causes etfs3 to fail to encap/work
            extended_stats=False,
        )

        testlib.save_stats(__name__, f"trex-stats-{ipsize}", trex_stats)
        testlib.save_stats(__name__, f"vpp-stats-{ipsize}", vstats)

        if trex:
            if (args.percentage <= 100):
                testlib.check_missed(args, trex_stats, vstats, vpplist)

            testlib.log_packet_counts(vpplist, trex_stats, vstats)

    logging.info("TEST PASSED")

    if args.pause_on_success:
        input("Pausing after test, RETURN to continue")

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

from trex_stl_lib.api import STLClient, STLFlowLatencyStats  # pylint: disable=C0413

from autovpp import testlib  # pylint: disable=C0413
from autovpp import trexlib  # pylint: disable=C0413


def calculate_max_bandwith(per_packet_clocks, packet_size):
    clocks_per_second = 2.1e9
    if not per_packet_clocks:
        return 0.0
    pps = clocks_per_second / per_packet_clocks
    packet_size += (14 + 4 + 8 + 12)
    packet_size *= 8
    return packet_size * pps


# Maybe take the user rate here.
def calculate_max_clocks(packet_size):
    clocks_per_second = 2.1e9
    packet_size += (14 + 4 + 8 + 12)
    packet_size *= 8
    pps = 10e9 / packet_size
    clocks_per_packet = clocks_per_second / pps
    return clocks_per_packet


async def run_test(args, trex, vpplist):  # pylint: disable=R0914
    c = STLClient(server=trex.connect_host)
    c.connect()

    ipsize = args.user_packet_size if args.user_packet_size else 576
    pps = testlib.line_rate_to_iptfs_encap_pps(args.rate, ipsize, args.iptfs_packet_size)
    if args.percentage:
        pps = pps * (args.percentage / 100)
    desc = f"Static IP Packet Size: {ipsize} @ {pps}pps for {args.duration}s"
    logging.info("Running %s", desc)

    def print_stats(beatsecs):
        del beatsecs  # unused

        # Just look at node 0
        logging.debug("  BEAT INFO: Updating node counters")
        vpp = vpplist[0]
        vpp.update_node_counters()
        for thread_index in sorted(vpp.thread_node_stats):
            if thread_index == 0:
                continue
            thread_stats = sorted(
                vpp.thread_node_stats[thread_index].values(),
                # key=lambda x: (256 - x.per_call_packets, x.per_packet_clocks),
                key=lambda x: x.per_packet_clocks,
                reverse=True)
            ppsum = 0.0
            for s in thread_stats:
                ppsum += s.per_packet_clocks

            pktsum = 0
            clksum = 0
            for s in thread_stats:
                pktsum += s.packets
                clksum += s.clocks
            ppsum2 = (clksum / pktsum) if pktsum else 0.0

            # This is wrong for pacer!
            lipsize = ipsize if thread_index in [1, 4] else args.iptfs_packet_size

            maxbw = calculate_max_bandwith(ppsum, lipsize)
            maxbw2 = calculate_max_bandwith(ppsum2, lipsize)
            maxclocks = calculate_max_clocks(lipsize)
            logging.debug(
                "%s", f"  BEAT INFO: Thread: {thread_index}; Total Per Packet Clock: {ppsum:8.0f}" +
                f" Max Bandwidth: {maxbw:15,.0f} Max Bandwidth2: {maxbw2:15,.0f}" +
                f" Avg Per Packet Clocks: {ppsum2:8.0f} Max Per Packet@10GE: {maxclocks:8.0f}")

            logging.debug(
                "%s", "{:<20} {:>15} {:>13} {:>13} {:>8} {:>7} {:>8} {:>16}".format(
                    "Node Name", "Calls", "Clocks", "Packets", "Clk/Call", "Pkt/Call", "Clk/Pkt",
                    "Max BW"))
            for s in thread_stats:
                if thread_index == 1:
                    if s.name == "iptfs-pacer":
                        lipsize = args.iptfs_packet_size
                    else:
                        lipsize = ipsize
                elif thread_index == 4:
                    lipsize = ipsize
                else:
                    lipsize = args.iptfs_packet_size
                maxbw = calculate_max_bandwith(s.per_packet_clocks, lipsize)
                logging.debug(
                    "%s", f"{s.name[-20:]:<20} {s.calls:>15} {s.clocks:>13} {s.packets:>13}"
                    f" {s.per_call_clocks:> 8.0f} {s.per_call_packets:> 8.3f}" +
                    f" {s.per_packet_clocks:> 8.0f} {maxbw:>16,.0f}")

    trex_stats, vstats, _ = await testlib.run_trex_cont_test(args,
                                                             c,
                                                             vpplist,
                                                             1,
                                                             trexlib.get_static_streams_seqnum,
                                                             imix_table=[{
                                                                 'size': ipsize,
                                                                 'pps': pps,
                                                                 'pg_id': 1,
                                                             }],
                                                             extended_stats=True,
                                                             beat_callback=print_stats,
                                                             beat_time=30,
                                                             statsclass=STLFlowLatencyStats)

    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

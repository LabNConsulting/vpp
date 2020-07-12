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

    if True:  # pylint: disable=W0125
        # Imix test
        imix_table = [
            {
                'size': 46,  # was 40, but breaking test is 60-14
                'pps': 28,
                'isg': 0,
            },
            {
                'size': 576,
                'pps': 16,
                'isg': 0.1,
            },
            {
                'size': 1500,
                'pps': 4,
                'isg': 0.2,
            }
        ]

        func = trexlib.get_static_streams
        # XXX may need to pass normalize option here??
        pps, ipsize, _ = testlib.update_table_with_rate(args, imix_table, args.rate,
                                                        args.iptfs_packet_size, args.percentage)
        desc = f"Imix (avg: {ipsize}) @ {pps}pps for {args.duration}s"
    else:
        # Spread test.
        if not args.user_packet_size:
            args.user_packet_size = 1500

        imix_table = [{
            'size': args.user_packet_size,
        }]

        spread_count = (args.user_packet_size + 1) - 40
        avg_ipsize = sum(range(40, args.user_packet_size + 1)) / spread_count
        pps = testlib.line_rate_to_iptfs_encap_pps(args.rate, avg_ipsize, args.iptfs_packet_size)
        if args.percentage:
            pps *= args.percentage / 100

        #func = trexlib.get_sequential_size_streams
        func = trexlib.get_sequential_size_iprange_streams
        desc = f"Spread (avg: {avg_ipsize}) @ {pps}pps for {args.duration}s"

    logging.info("Running %s", desc)

    def beatfunc(beatsecs):
        del beatsecs  # unused
        # stats = c.get_stats()
        # if stats and "flow_stats" in stats and "global" in stats["flow_stats"]:
        #     logging.debug("TREX: flow_stats: %s", pprint.pformat(stats["flow_stats"]["global"]))
        # logging.debug(
        #     f'TREX: {beatsecs}: port0 tx {stats[0]["opackets"]} port1 rx {stats[1]["ipackets"]}')
        # logging.debug(
        #     f'TREX: {beatsecs}: port1 tx {stats[1]["opackets"]} port0 rx {stats[0]["ipackets"]}')
        for vpp in vpplist:
            try:
                combined, _, _, _, errors, = vpp.get_tun_stats()
            except Exception:
                logging.warning("%s", f"Couldn't get stats from {vpp.name}")
                continue
            # rxpad = pkts[0]["/net/ipsec/sa/iptfs/decap-rx-pad-datablock"]
            # rxpad_octets = octets[0]["/net/ipsec/sa/iptfs/decap-rx-pad-datablock"]
            vpperrs = []
            for error_name in errors:
                error = errors[error_name]
                if error:
                    error_name = error_name[error_name.rfind("/") + 1:]
                    vpperrs.append(f"{error_name}: {error}")
            if vpperrs:
                logging.debug("VPPERR: %s: %s", vpp.name, ", ".join(vpperrs))
            vppstats = []
            for sai in sorted(combined):
                sa_stats = combined[sai]
                for stat_name in sorted(sa_stats):
                    sa_stat = sa_stats[stat_name]
                    if sa_stat:
                        stat_name = stat_name[stat_name.rfind("/") + 1:]
                        vppstats.append(f"{stat_name}: {sa_stat}")
            if vppstats:
                logging.debug("VPPSTAT: %s: %s", vpp.name, ", ".join(vppstats))

    trex_stats, vstats, _ = await testlib.run_trex_cont_test(args,
                                                             c,
                                                             vpplist,
                                                             pps,
                                                             func,
                                                             imix_table=imix_table,
                                                             beat_callback=beatfunc,
                                                             beat_time=1,
                                                             extended_stats=True)

    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

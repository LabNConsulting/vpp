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

    if args.user_packet_size:
        ipsizes = [args.user_packet_size]
    elif args.null:
        ipsizes = [
            40, 46, 100, 128, 150, 200, 256, 500, 512, 576, 768, 1000, 1466, 1500, 4500, 9000
        ]
    else:
        ipsizes = [
            40, 46, 100, 128, 150, 200, 256, 500, 512, 576, 768, 1000, 1442, 1500, 4500, 9000
        ]

    for ipsize in ipsizes:
        pps = testlib.line_rate_to_iptfs_encap_pps(args.rate, ipsize, args.iptfs_packet_size)
        desc = f"Static IP Packet Size: {ipsize} @ {pps}pps for {args.duration}s"
        logging.info("Running %s", desc)

        pad_frags = [[], []]

        def print_pads(beatsecs):
            def add_frags(vpp_index, vpp):
                _, _, pkts, octets, _, = vpp.get_tun_stats()
                rxpad = pkts[0]["/net/ipsec/sa/iptfs/decap-rx-pad-datablock"]
                rxpad_octets = octets[0]["/net/ipsec/sa/iptfs/decap-rx-pad-datablock"]
                # XXX not understanding the pylint warning here, may be important
                pad_frags[vpp_index].append((rxpad, rxpad_octets))
                logging.debug(
                    "%s",
                    f"  BEAT INFO {beatsecs}: {vpp.host} rxpad: {rxpad} (octets: {rxpad_octets})")

            for vppi, vpp in enumerate(vpplist):
                add_frags(vppi, vpp)

        if not args.capture_drops:
            args.capture_drops = 10

        trex_stats, vstats, _ = await testlib.run_trex_cont_test(args,
                                                                 c,
                                                                 vpplist,
                                                                 1,
                                                                 trexlib.get_static_streams,
                                                                 imix_table=[{
                                                                     'size': ipsize,
                                                                     'pps': pps,
                                                                 }],
                                                                 extended_stats=True,
                                                                 beat_callback=print_pads,
                                                                 beat_time=2)

        testlib.save_stats(__name__, f"trex-stats-{ipsize}", trex_stats)
        testlib.save_stats(__name__, f"vpp-stats-{ipsize}", vstats)

        USER_IFINDEX = 1

        #
        # Verify trex received all it sent.
        #
        p0missed = trex_stats[0]["rx-missed"]
        p1missed = trex_stats[1]["rx-missed"]
        if p0missed or p1missed:
            reason = f"FAILED: p0missed: {p0missed} p1missed: {p1missed}"
            testlib.fail_test(args, reason, trex_stats, vstats, vpplist)

        #
        # Verify trex received all VPP sent.
        #
        for i in range(0, 2):
            trx = trex_stats[0]["ipackets"]
            vuser_tx = vstats[0][USER_IFINDEX]["/if/tx"]
            if trx != vuser_tx:
                reason = f"FAILED: vpp{i}/trex port{i} vuser_tx: {vuser_tx} != prx: {trx}"
                testlib.fail_test(args, reason, trex_stats, vstats, vpplist)

        #
        # Diagnostic to turn into test of padding when it works.
        #
        for vppi, vpp in enumerate(vpplist):
            _, _, pkts, octets, _, = vpp.get_tun_stats()
            sai = 0
            init_rxpad = pad_frags[vppi][0][0]
            init_rxpad_octets = pad_frags[vppi][0][1]

            stop_rxpad = pad_frags[vppi][-1][0]
            stop_rxpad_octets = pad_frags[vppi][-1][1]

            rxpad = pkts[sai]["/net/ipsec/sa/iptfs/decap-rx-pad-datablock"]
            rxpad_octets = octets[sai]["/net/ipsec/sa/iptfs/decap-rx-pad-datablock"]
            if init_rxpad != stop_rxpad:
                reason = (f"Too many pad fragments: {vpp.host}:{sai} " +
                          f"post-init pad: {init_rxpad}:{init_rxpad_octets} " +
                          f"pre-stop pad: {stop_rxpad}:{stop_rxpad_octets} " +
                          f"total rxpad: {rxpad} frags {rxpad_octets} octets")
                #fail_test(args, reason, trex_stats, vstats, vpplist)
                logging.error("  FAIL %s", reason)
            else:
                logging.info(
                    "%s", f"  INFO: {vpp.host}:{sai} " +
                    f"post-init pad: {init_rxpad}:{init_rxpad_octets} " +
                    f"pre-stop pad: {stop_rxpad}:{stop_rxpad_octets} " +
                    f"total rxpad: {rxpad} frags {rxpad_octets} octets")

        # logging.debug("TREX Stats:\n%s" % pprint.pformat(trex_stats, indent=4))

        logging.info("TEST INFO: [ tx/rx: {} ]".format([
            (vstats[x][USER_IFINDEX]["/if/tx"], trex_stats[x]["ipackets"]) for x in range(0, 2)
        ]))

        logging.info("TEST PASSED")

        if args.pause_on_success:
            input("Pausing after test, RETURN to continue")

    # results = {
    #     'description': desc,
    #     'duration': str(duration),
    #     'imix': imix_table,
    #     'statistics': {
    #         "0": stats[0],
    #         "1": stats[1],
    #     }
    # }
    # print(json.dumps(results, indent=4, separators=(',', ': '), sort_keys=True), file=sys.stderr)
    # print(file=sys.stderr)

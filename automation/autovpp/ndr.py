# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 11 2021, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2021 LabN Consulting, L.L.C.
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
"""
A module of utility functions for No Drop Test.
"""

import asyncio
import datetime
import logging
import time

import autovpp.testlib as testlib

logger = logging.getLogger(__name__)


def get_active_vpp(l):
    a = []
    for v in l:
        if v.check_running():
            a.append(v)
        else:
            logger.warning("%s exited", v.name)
    return a


def check_active_vpp(vpplist):
    active_vpplist = get_active_vpp(vpplist)
    if active_vpplist != vpplist:
        for v in vpplist:
            if v not in active_vpplist:
                v.gather_any_core_info()
        raise Exception("Not all vpp are running")


async def run_ndr_interval(args, c, vpplist, rate, cf):
    check_active_vpp(vpplist)

    # Remove TFS config
    for v in vpplist:
        v.remove_tfs_config(args, fail_ok=True)

    check_active_vpp(vpplist)

    # Add TFS config
    for v in vpplist:
        v.add_tfs_config(args)

    check_active_vpp(vpplist)

    check_ports, _ = cf(c, rate)

    vargs = vars(args)
    extended_stats = vargs["extended_stats"] if "extended_stats" in vargs else False

    testlib.clear_stats(c, vpplist, extended_stats, False)

    # # Try sending a short burst of the test to prime the pump.
    # if c:
    #     prime_duration = .1
    #     logger.debug("Pre-starting TREX: to prime the pump: duration: %s", str(prime_duration))
    #     c.start(ports=check_ports, duration=prime_duration)
    #     c.wait_on_traffic(rx_delay_ms=100)
    #     testlib.clear_stats(c, vpplist, extended_stats, False)

    starttime = datetime.datetime.now()
    endtime = starttime + datetime.timedelta(0, args.duration)
    c.start(ports=check_ports, duration=args.duration)

    beat_stats = []

    def collect_trex_stats(_):
        beat_stats.append(testlib.collect_trex_stats(args, c))

    testlib.wait_for_test_done(vpplist, c, check_ports, starttime, endtime, collect_trex_stats)

    check_active_vpp(vpplist)

    max_rx_pps = max([x[1]["rx_pps"] for x in beat_stats])
    vstats = await asyncio.gather(*[testlib.collect_vpp_stats(x, extended_stats) for x in vpplist])
    stats = testlib.collect_trex_stats(args, c)

    check_active_vpp(vpplist)
    return max_rx_pps, stats[0]["rx-missed-pct"], stats[1]["rx-missed-pct"], stats, vstats


async def run_ndr_intervals(args, c, vpplist, cf, high_pct, low_pct, pdr=0.001):
    pct = high_pct
    last_fail_pct = None
    last_ok_pct = low_pct
    last_ok_results = (None, None)
    last_fail_results = (None, None)
    count = 10
    for interval in range(0, count):
        rate = args.rate * pct
        hrate = testlib.get_human_readable(rate)
        logger.info("%s",
                    f"Running interval {interval + 1}: rate {hrate} ({pct*100}% of {args.rate})")
        max_rx_pps, drop0, drop1, stats, vstats = await run_ndr_interval(args, c, vpplist, rate, cf)
        rx_pps_human = testlib.get_human_readable(max_rx_pps)

        errors = stats[0]["ierrors"] + stats[0]["oerrors"]
        errors += stats[1]["ierrors"] + stats[1]["oerrors"]
        q_full = stats["global"]["queue_full"] if "queue_full" in stats["global"] else 0
        errors += q_full
        if drop0 <= pdr and drop1 <= pdr and not errors:
            # Success
            logger.info(
                "%s",
                f"Acceptable drop rate of ({drop0}%, {drop1}%) < {pdr} TX {hrate}bps MAXRX: {rx_pps_human}pps"
            )
            last_ok_pct = pct
            last_ok_results = (max_rx_pps, pct, drop0, drop1, stats, vstats)
            if last_fail_pct is None:
                logger.info(
                    "%s",
                    f"Acceptable first drop rate of ({drop0}%, {drop1}%) < {pdr} TX {hrate}bps MAXRX: {rx_pps_human}pps)"
                )
                return last_ok_results, last_fail_results
            # increase to halfway between last fail and this one.
            pct += (last_fail_pct - pct) / 2
            delay = 1
        else:
            if errors:
                logger.warning(
                    "%s",
                    f'''TREX Errors: ierrors port 0/1: {stats[0]["ierrors"]}/{stats[1]["ierrors"]}
                        oerrors: port 0/1 {stats[0]["oerrors"]}/{stats[1]["oerrors"]}
                        q_full: {q_full}
                        TX {hrate}bps MAXRX: {rx_pps_human}pps''')
            else:
                logger.info(
                    "%s",
                    f"Unacceptable drop rate of ({drop0}%, {drop1}%) < {pdr} TX {hrate}bps MAXRX: {rx_pps_human}pps"
                )
            last_fail_pct = pct
            last_fail_results = (max_rx_pps, pct, drop0, drop1, stats, vstats)
            pct -= (pct - last_ok_pct) / 2
            delay = 10

        if interval + 1 < count:
            logging.info("%s", f"Sleeping {delay}s")
            time.sleep(delay)

    return last_ok_results, last_fail_results


async def find_ndr(args, c, vpplist, cf):
    logger.info("Starting TREX NDR")
    pdr = args.partial_drop_rate if args.partial_drop_rate is not None else 0.001
    ok_results, fail_results = await run_ndr_intervals(args, c, vpplist, cf, 1.0, 0, pdr=pdr)
    logger.debug("TREX: after find_ndr")
    return ok_results, fail_results

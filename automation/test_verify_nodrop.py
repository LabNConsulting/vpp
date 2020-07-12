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
import pprint
import time

from autovpp import testlib
from autovpp import trexlib
from trex_stl_lib.api import STLClient


async def run_test(args, trex, vpplist):  # pylint: disable=R0914
    if not trex:
        c = None
    else:
        c = STLClient(server=trex.connect_host, sync_timeout=10, async_timeout=10)
        for i in range(0, 11):
            try:
                c.connect()
            except Exception as ex:
                if i == 10:
                    raise
                print("Failed to connect to trex, retry")
                time.sleep(1)

    imix_table, pps, avg_ipsize, imix_desc = testlib.get_imix_table(args, c)
    desc = f"Verify no drop {imix_desc} for {args.duration}s"

    logging.info("Running %s", desc)

    def beatfunc(beatsecs):
        logging.debug("%s", f"BEAT INFO {beatsecs}")
        if c:
            stats = c.get_stats()
            if stats and "flow_stats" in stats and "global" in stats["flow_stats"]:
                gfs = stats["flow_stats"]["global"]
                gfs = {k: v for k, v in gfs.items() if sum(v.values())}
                if gfs:
                    logging.debug("  TREX Flow stats: %s", pprint.pformat(gfs))
        for vpp in vpplist:
            vpp.update_interface_counters()
            _, _, _, _, errors, = vpp.get_tun_stats()
            errors = {k: v for k, v in errors.items() if v}
            if errors:
                logging.debug("%s", f"  {vpp.host} errors:\n{pprint.pformat(errors)}")
            rx_misses = ""
            for i in vpp.intf_stat_counters_i:
                missval = vpp.intf_stat_counters_i[i]["/if/rx-miss"]
                if missval:
                    desc = "USER" if i == vpp.USER_IFINDEX else "TFS"
                    rx_misses += f"{desc} ({vpp.ifnames[i]}): {missval} "
            if rx_misses:
                logging.debug("%s", f"  {vpp.host} misses:\n{pprint.pformat(rx_misses)}")

    trex_stats, vstats, _ = await testlib.run_trex_cont_test(args,
                                                             c,
                                                             vpplist,
                                                             1,
                                                             trexlib.get_static_streams_simple,
                                                             imix_table=imix_table,
                                                             extended_stats=False,
                                                             beat_callback=beatfunc,
                                                             beat_time=1)

    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

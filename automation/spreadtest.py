# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 23 2020, Christian E. Hopps <chopps@labn.net>
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
from trex_stl_lib.api import STLClient


async def run_test(args, trex, vpplist, func):
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

    if not args.user_packet_size:
        args.user_packet_size = 1500

    imix_table, _, _, desc = testlib.get_udp_spread_table(args, c)

    logging.info("Running %s", desc)

    trex_stats, vstats, _ = await testlib.run_trex_cont_test(args,
                                                             c,
                                                             vpplist,
                                                             1,
                                                             func,
                                                             imix_table=imix_table,
                                                             extended_stats=True)

    testlib.finish_test(__name__, args, vpplist, trex, trex_stats, vstats)

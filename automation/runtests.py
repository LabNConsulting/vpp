#!/usr/bin/env python3
# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 8 2020, Christian E. Hopps <chopps@labn.net>
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
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes

import asyncio
import glob
import logging
import os
import subprocess
import sys
import time
from traceback import print_exc

from autovpp import remote
from autovpp import runlib
from autovpp.vpppath import g_g2, g_c2cpel

UINT_NULL = 4294967295


# def main(*margs):
async def main_after_up(args, vpplist, trex, other):
    if not args.tests:
        while input("Testbed is UP, enter \"q\" to exit").strip() != "q":
            pass
    else:
        if args.cc:
            logging.info("Waiting 4 seconds for CC slow-start")
            time.sleep(4)

        for testarg in args.tests:
            slashi = testarg.rfind("/")
            testname = testarg[slashi + 1:]
            testpath = testarg[:slashi]
            if testpath and testpath not in sys.path:
                sys.path.append(testpath)
            if testname.endswith(".py"):
                testname = testname[:-3]
            test_module = __import__(f"{testname}", globals())
            try:
                await test_module.run_test(args, trex, vpplist)  # pylint: disable=E0602
            except subprocess.CalledProcessError as error:
                logging.error("%s",
                              f"Failed to run test: error: {testarg}: {error}: {error.output}")
                if args.verbose:
                    print_exc()
            except Exception as ex:
                logging.error("%s", f"Failed to run test: exception: {testarg}: {ex}")
                if args.verbose:
                    print_exc()
            if testpath and testpath in sys.path:
                sys.path.remove(testpath)

        if args.event_log_cpel:
            if not g_c2cpel:
                logging.warning("No c2cpel binary for conversion")
            else:
                for f in glob.glob("*.clib"):
                    remote.run_cmd(
                        f"{g_c2cpel} --input-file {f} --output-file {f.replace('.clib', '.cpel')} && rm {f}"
                    )

        if args.view_event_logs:
            if not os.environ["DISPLAY"]:
                logging.warning("Skipping display of event logs: DISPLAY not set")
            else:
                # Launch g2 on event logs
                if args.event_log_cpel:
                    for f in glob.glob("*.cpel"):
                        remote.run_bg_cmd(f"{g_g2} --cpel-input {f}", True)
                else:
                    for f in glob.glob("*.clib"):
                        remote.run_bg_cmd(f"{g_g2} --clib-input {f}", True)

        if args.pause:
            while input("Pausing with testbed UP, enter \"q\" to exit").strip() != "q":
                pass

    for vpp in vpplist:
        vpp.close()

    if len(other) > 2 and other[2]:
        for sshd in other[2]:
            sshd.close()

    print(f"Logs in: {args.logsdir}")


# def main(*margs):
async def main(*margs):

    parser, _, _ = runlib.init_std_args()
    args = parser.parse_args(*margs)
    runlib.finalize_args(args)

    runlib.logdir_init_cd(args)

    vpplist, trex, other = runlib.init_all_up(args)
    try:
        await main_after_up(args, vpplist, trex, other)
    except Exception:
        if len(other) > 1:
            for server in other[1]:
                server.stop()
            for server in other[1]:
                server.close()
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as ex:
        logging.error("Got Exception in main: %s", str(ex))
        print_exc()
        while input("Pausing with testbed UP, enter \"q\" to exit").strip() != "q":
            pass
        sys.exit(0)

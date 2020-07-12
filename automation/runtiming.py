#!/usr/bin/env python3
# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# June 16 2020, Christian Hopps <chopps@labn.net>
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
import asyncio
import logging
import os
import subprocess
import sys
from traceback import print_exc

from autovpp import runlib
# from autovpp.vpppath import g_g2, g_vpp_srcdir, g_def_logsdir

UINT_NULL = 4294967295


# def main(*margs):
async def main(*margs):
    parser, runargs, setupargs = runlib.init_std_args()
    runargs.add_argument(
        "--timing-mrates",
        nargs="*",
        type=runlib.spacecommalist,
        # default=["10", "100", "500", "1000", "2000", "5000", "10000"],
        default=["10", "100", "500", "1000"],
        help="comma or space separated list of megabit L2 rates.")
    runargs.add_argument("--timing-percents",
                         nargs="*",
                         type=runlib.spacecommalist,
                         default=["0", "50", "100"],
                         help="comma or space separated list of traffic percentage to send.")
    args = parser.parse_args(*margs)
    runlib.finalize_args(args)

    if not args.tests:
        args.tests = ["test_verify_timing.py"]
    if not args.capture_snaplen:
        args.capture_snaplen = 64

    runlib.logdir_init_cd(args)

    # args.logdir is now the parent logdir for each iteration of the timing tests.

    # If we don't have a percentage, runlib wont launch trex
    args.percentage = float(100)

    vpplist, trex, other = runlib.init_all_up(args)

    for mrate in args.timing_mrates:
        mrate = int(mrate)
        args.rate = mrate * 1000000
        logging.info("%s", f"Starting runs with speed {mrate}M")

        for pct in args.timing_percents:
            args.percentage = float(pct)
            logging.info("%s", f"Starting runs with traffic pct {pct}%")

            for testarg in args.tests:
                slashi = testarg.rfind("/")
                testname = testarg[slashi + 1:]
                basename = testname.replace("test_", "")
                testpath = testarg[:slashi]
                if testpath:
                    sys.path.append(testpath)

                if testname.endswith(".py"):
                    testname = testname[:-3]

                newlogdir = os.path.join(args.logdir, f"{mrate}M-{pct}-{basename}")
                os.makedirs(newlogdir, mode=0o755, exist_ok=True)
                os.chdir(newlogdir)
                try:
                    exec(f"import {testname} as test_module", globals())  # pylint: disable=W0122
                    try:
                        await test_module.run_test(args, trex, vpplist)  # pylint: disable=E0602
                        # test_module.run_test(args, trex, vpplist)
                    except subprocess.CalledProcessError as error:
                        logging.error(
                            "%s", f"Failed to run test: error: {testarg}: {error}: {error.output}")
                        if args.verbose:
                            print_exc()
                    except Exception as ex:
                        logging.error("%s", f"Failed to run test: exception: {testarg}: {ex}")
                        if args.verbose:
                            print_exc()
                finally:
                    os.chdir(args.logdir)

                if testpath:
                    sys.path.remove(testpath)

        # Now we have a run of pcts at a given speed. Let's collect the data on them, and save as
        # summaries.

    # if args.view_event_logs:
    #     if not os.environ["DISPLAY"]:
    #         logging.warning("Skipping display of event logs: DISPLAY not set")
    #     else:
    #         # Launch g2 on event logs
    #         for f in glob.glob("*.clib"):
    #             remote.run_bg_cmd(f"{g_g2} --clib-input {f}", True)

    if args.pause:
        while input("Pausing with testbed UP, enter \"q\" to exit").strip() != "q":
            pass

    for vpp in vpplist:
        vpp.close()

    if len(other) > 2 and other[2]:
        for sshd in other[2]:
            sshd.close()

    print(f"Logs in: {args.logsdir}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as ex:
        logging.error("Got Exception in main: %s", str(ex))
        print_exc()
        while input("Pausing with testbed UP, enter \"q\" to exit").strip() != "q":
            pass
        sys.exit(0)

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

import os
import logging

from autovpp import testlib
from autovpp import trexlib
from trex_stl_lib.api import STLClient


#
# This test shows:
# data integrity of etfs encap/decap
#
async def run_test(args, trex, vpplist):  # pylint: disable=R0914
    # Does not use trex
    # uses scp to transfer data

    # We assume two vpp instances 
    vpp1 = vpplist[0]
    vpp2 = vpplist[1]

    # Find a suitable large file on the remote host
    cmd = "ls /boot/vmlinuz*"
    returncode, output = vpp1.remote_cmd_status(cmd)
    if returncode:
        logging.info("Failed, can't get target file list")
        raise Exception("can't get target file list")

    for li in output.splitlines():
        filename = li
        break

    logging.info(f"using filename {filename}")


    cmd = "scp"
    cmd += f" -o StrictHostKeyChecking=no"
    cmd += f" -P {vpp2.integrity_portnumber}"
    cmd += f" {vpp2.integrity_ipaddr}:{filename} /dev/null"
    logging.info(f"STARTING TEST (cmd {cmd})")
    returncode, output = vpp1.remote_cmd_status(cmd)
    if returncode:
        logging.info(f"Failed, code={returncode}")
        raise Exception("scp failed")

    logging.info(f"TEST PASSED")
    if args.pause_on_success:
        input("Pausing after test, RETURN to continue")

    #
    # cleanup
    #
    # This part shares knowledge of the temporary veth interface names
    # with the creation code in runetfs.sh. TBD figure out a good way
    # to unify the creation and cleanup so it is harder for them to get
    # out of sync.
    #
    USER=os.environ['USER']
    interface=f"vev-{USER}"

    cmd = f"sudo ip link delete {interface}"
    for v in vpplist:
        logging.debug(f"cleaning up veth interface {interface}")
        returncode, output = v.remote_cmd_status(cmd)
        if returncode:
            logging.info(f"Failed interface cleanup on vpp host {v.host}")
            logging.info(f"Failed output: {output}")

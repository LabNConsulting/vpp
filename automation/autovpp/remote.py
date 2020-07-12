# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 12 2020, Christian E. Hopps <chopps@labn.net>
#
# Copyright (c) 2020, LabN Consulting, L.L.C
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
A module for running things on remote machines.
"""
import atexit
import datetime
import json
import logging
import os
import re
import pdb
import shlex
import socket
import subprocess
import tempfile
import threading
import time
from collections import defaultdict, namedtuple

import pexpect

from .vpppath import g_vpp_maj_version, g_vpp_native_root, g_vpp_srcdir

from vpp_papi import VPPApiClient
from vpp_papi import VPPApiJSONFiles
from vpp_papi import VPPIOError

from autovpp.tbdata import testbed_binonly, testbed_interfaces, testbed_docker_physical

NodeStats = namedtuple(
    "NodeStats",
    "name calls clocks packets suspends per_call_clocks per_call_packets per_packet_clocks")

logger = logging.getLogger(__name__)
cmd_logger = logging.getLogger(__name__ + ".cmd")

STYPE_SCALAR_INDEX = 1
STYPE_COUNTER_VECTOR_SIMPLE = 2
STYPE_COUNTER_VECTOR_COMBINED = 3
STYPE_ERROR_INDEX = 4
STYPE_NAME_VECTOR = 5

UINT_NULL = 4294967295

# from vpp_papi.vpp_transport_shmem import VppTransportShmemIOError

# # This is not thread safe, might need to make async safe.
# def get_apifiles(host, api_dir):
#     from vpp_papi import VPPApiJSONFiles
#     with get_apifiles.lock:
#         if not get_apifiles.apifiles:
#         return get_apifiles.apifiles

# # Static variables for above function
# get_apifiles.apifiles = None
# get_apifiles.lock = threading.Lock()

#
# Get the commands paths
#

g_bg_procs = []


def run_cmd_status(cmd, encoding="utf-8", logger=None):
    process = subprocess.run(cmd,
                             shell=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             check=False,
                             encoding=encoding)
    output = process.stdout.strip()
    # Log the result
    if logger is None:
        logger = cmd_logger
    if logger:
        if process.returncode:
            logger.warning('CMD FAIL: returncode %d stdout/stderr: "%s" for cmd: "%s"',
                           process.returncode, output, cmd)
        else:
            logger.debug('CMD OK: stdout/stderr: "%s" for cmd: "%s"', output, cmd)

    return process.returncode, output


def run_cmd(cmd, encoding="utf-8", logger=None):
    status, output = run_cmd_status(cmd, encoding, logger)
    if status:
        e = subprocess.CalledProcessError(cmd=cmd, returncode=status, output=output)
        raise e
    return output


def run_cmd_status_error(cmd, encoding="utf-8", logger=None):
    process = subprocess.run(cmd,
                             shell=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             check=False,
                             encoding=encoding)

    output = process.stdout.strip()
    error = process.stderr.strip()
    # Log the result
    if logger is None:
        logger = cmd_logger
    if logger:
        if process.returncode:
            logger.warning('CMD FAIL: returncode: %d stdout: "%s" stderr: "%s" for cmd: "%s"',
                           process.returncode, output, error, cmd)
        else:
            logger.debug('CMD OK: stdout: "%s" stderr: "%s" for cmd: "%s"', output, error, cmd)

    return process.returncode, output, error


def run_cmd_error(cmd, encoding="utf-8", logger=None):
    status, output, error = run_cmd_status_error(cmd, encoding, logger)
    if status:
        raise subprocess.CalledProcessError(cmd=cmd, returncode=status, output=output, stderr=error)
    return output, error


# Maybe need to fix this to cleanup on exit, although we count on it *not* doing so for event
# viewer?
def run_bg_cmd(cmd, detach=False, logger=None):
    process = subprocess.Popen(cmd,
                               shell=True,
                               close_fds=True,
                               start_new_session=detach,
                               stdin=subprocess.DEVNULL)
    if process.poll():
        raise Exception(f"Popen failed: returncode: {process.returncode}")
    if not detach:
        g_bg_procs.append(process)
    if logger is None:
        logger = cmd_logger
    logger.debug('BG CMD OK: "%s"', cmd)


def remote_cmd_status(host, cmd, encoding="utf-8", logger=None):
    # escape ' character since we use it  in our cmd line to quote the cmd
    cmd = cmd.replace("'", "'\"'\"'")
    if not encoding:
        cmdline = f"ssh -q {host} '{cmd}'"
    else:
        cmdline = f"ssh -q -tt {host} '{cmd}'"
    return run_cmd_status(cmdline, encoding=encoding, logger=logger)


def remote_cmd_status_error(host, cmd, encoding="utf-8", logger=None):
    cmd = cmd.replace("'", "'\"'\"'")
    if not encoding:
        cmdline = f"ssh -q {host} '{cmd}'"
    else:
        cmdline = f"ssh -q -tt {host} '{cmd}'"
    return run_cmd_status_error(cmdline, encoding=encoding, logger=logger)


def remote_cmd(host, cmd, encoding="utf-8", logger=None):
    cmd = cmd.replace("'", "'\"'\"'")
    if not encoding:
        cmdline = f"ssh -q {host} '{cmd}'"
    else:
        cmdline = f"ssh -q -tt {host} '{cmd}'"
    return run_cmd(cmdline, encoding=encoding, logger=logger)


def remote_cmd_error(host, cmd, encoding="utf-8", logger=None):
    cmd = cmd.replace("'", "'\"'\"'")
    if not encoding:
        cmdline = f"ssh -q {host} '{cmd}'"
    else:
        cmdline = f"ssh -q -tt {host} '{cmd}'"
    return run_cmd_error(cmdline, encoding=encoding, logger=logger)


def check_port(host, port, timeout=30):
    enter = datetime.datetime.now()
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            sock.close()
            return True
        except socket.error:
            if (datetime.datetime.now() - enter).total_seconds() > timeout:
                return False


class Process:
    def __init__(self, pname, host, cmd, ssh_opts="", is_docker=False):
        self.output = ""
        self.host = host if host else ""

        self.is_docker = is_docker

        if host:
            self.name = f"{pname}-{host}"
        else:
            self.name = f"{pname}"
        self.binary_output = b""
        self.process = None
        if not cmd:
            return

        self.docker_exec = ""
        if self.is_docker:
            self.cont_id = run_cmd(
                f"docker-compose -f {g_vpp_srcdir}/automation/docker-compose.yml ps -q {host}")
            self.cont_pid = run_cmd(
                f"docker inspect --format='{{{{ .State.Pid }}}}' {self.cont_id}")
            self.docker_exec = f"docker exec {self.cont_id}"
            self.docker_exec_tty = f"docker exec -it {self.cont_id}"

        self.shell = None
        self.shell_prompt_set = '#$?#EXPECT#'
        self.shell_prompt_regex = '#([0-9]+)#EXPECT#'
        self.output_filename = f"{self.name}.log"
        self.output_filename = f"{self.name}.log"
        self.output_file = open(self.output_filename, "w+")
        self.cmdline = self.get_host_cmd_list(cmd, ssh_opts)
        self.binary_filename = None
        self.binary_file = None
        stdout = self.output_file
        stderr = subprocess.STDOUT
        logger.debug(f"Running: {self.name}: command: {self.cmdline}")
        logger.debug(f'       : {" ".join(self.cmdline)}')
        # It is critical that we do the following so that commands are cleaned up
        # - Do not use shell=True (otherwise bash just exits leaving process running)
        # - Do use "-tt" to ssh, otherwise ssh just exists leaving commands running
        self.process = subprocess.Popen(self.cmdline,
                                        shell=False,
                                        stdin=subprocess.DEVNULL,
                                        stdout=stdout,
                                        stderr=stderr)
        self.check_process()
        g_bg_procs.append(self)

    def get_host_cmd_list(self, cmd, ssh_opts=""):
        if self.is_docker:
            assert self.docker_exec
            cmdline = shlex.split(f"{self.docker_exec} bash -c ")
            cmdline.append(cmd)
        elif self.host:
            cmdline = shlex.split(f"ssh -q -tt {ssh_opts} {self.host}")
            cmdline.append(cmd)
        else:
            cmdline = shlex.split(f"{cmd}")
        return cmdline

    def get_host_cmd_string(self, cmd, ssh_opts=""):
        if self.is_docker:
            assert self.docker_exec
            cmd = shlex.quote(cmd)
            cmdline = f"{self.docker_exec} bash -c {cmd}"
        elif self.host:
            cmd = shlex.quote(cmd)
            cmdline = f"ssh -q -tt {ssh_opts} {self.host} {cmd}"
        else:
            cmdline = shlex.quote(cmd)
        return cmdline

    def _get_output(self):
        if self.binary_file:
            self.binary_file.close()
            self.binary_file = None
            with open(self.binary_filename, "rb") as f:
                self.binary_output = f.read()
        if self.output_file:
            self.output_file.close()
            self.output_file = None
            with open(self.output_filename, "r") as f:
                self.output = f.read()

    def check_process(self):
        status = self.process.poll()
        if status:
            self._get_output()
            raise Exception(f"Popen failed: {self.process.returncode}: \"{self.output}\"")

    def check_port(self, host, port, timeout=30):
        if not check_port(host, port, timeout):
            self.close()
            errstr = f'Timeout checking for host:port {host}:{port}.\noutput: "{self.output}"'
            logger.error("%s", errstr)
            raise Exception(errstr)

    def close(self):
        # print("Closing: " + self.cmdline)
        try:
            if self.shell:
                self.shell.close()
                self.shell = None
            if self.process:
                for _ in range(0, 10):
                    if self.process.poll() is not None:
                        break
                    logger.debug(f"Sending SIGTERM to {self.name}")
                    self.process.terminate()
                    try:
                        self.process.wait(1)
                    except subprocess.TimeoutExpired:
                        pass
                if self.process.poll() is None:
                    logger.debug(f"Sending SIGKILL to {self.name}")
                    self.process.kill()
                self.process.wait()
                self._get_output()
                self.process = None
            if self in g_bg_procs:
                g_bg_procs.remove(self)
        except Exception as ex:
            logger.error(f"Bad close: {ex}")

    def get_remote_file(self, filename):
        return self.remote_cmd(f"sudo cat {filename}", encoding=None)

    def remote_cmd(self, cmd, encoding="utf-8"):
        if self.is_docker:
            return run_cmd(f"{self.docker_exec} {cmd}", encoding)
        return remote_cmd(self.host, cmd, encoding)

    def remote_cmd_error(self, cmd, encoding="utf-8"):
        if self.is_docker:
            return run_cmd_error(f"{self.docker_exec} {cmd}", encoding)
        return remote_cmd_error(self.host, cmd, encoding)

    def remote_cmd_status(self, cmd, encoding="utf-8"):
        if self.is_docker:
            return run_cmd_status(f"{self.docker_exec} {cmd}", encoding)
        return remote_cmd_status(self.host, cmd, encoding)

    def remote_cmd_status_error(self, cmd, encoding="utf-8"):
        if self.is_docker:
            return run_cmd_status_error(f"{self.docker_exec} {cmd}", encoding)
        return remote_cmd_status_error(self.host, cmd, encoding)

    def get_shell(self, suffix=""):
        shell_logfile = open(f"shell-{self.name}{suffix}.txt", "wb")
        shell = pexpect.spawn(self.shell_cmd, logfile=shell_logfile)
        shell.setwinsize(1000, 1000)
        shell.expect("^.*[\#\$]")
        shell.sendline(f"PS1='{self.shell_prompt_set}'")
        shell.expect(re.escape(self.shell_prompt_set))
        shell.expect(self.shell_prompt_regex)
        shell.sendline("stty -onlcr")
        shell.expect("stty -onlcr")
        shell.expect(self.shell_prompt_regex)
        shell.sendline("TERM=dumb")
        shell.expect(self.shell_prompt_regex)
        return shell

    def remote_shell_cmd_status(self, cmd, shell=None, no_capture=False):
        if shell is None:
            if self.shell is None:
                self.shell = self.get_shell()
            shell = self.shell
        shell.sendline(cmd)
        if no_capture:
            shell.expect(re.escape(cmd) + "\n")
            return 0, ""
        shell.expect(self.shell_prompt_regex)
        status = int(shell.match.group(1))
        output = shell.before
        output = output.decode().replace('\r', '')
        assert output.startswith(cmd + "\n")
        return status, output[len(cmd) + 1:].rstrip()

    def remote_shell_cmd(self, cmd, shell=None, no_capture=False):
        status, output = self.remote_shell_cmd_status(cmd, shell, no_capture)
        if not status:
            return output
        if status > 128:
            status = -(status - 128)
        raise subprocess.CalledProcessError(cmd=cmd, returncode=status, output=output)

    # Walk like a Popen object.
    def terminate(self):
        return self.close()

    def __del__(self):
        try:
            if self.process:
                logger.error(f"__del__({self.name})")
                self.process.kill()
                self.process.wait()
            if self in g_bg_procs:
                g_bg_procs.remove(self)
        except Exception as ex:
            logger.error(f"Bad __del__: {ex}")


class PCapServer(Process):
    def __init__(self, args, port, host=None, snaplen=None):
        """Run a capture on a host"""
        self.port = port
        self.pcapname = f"/tmp/pcap-server-{port}.pcap"
        snaparg = f"-s {snaplen}" if snaplen else ""
        if args.is_docker or not host:
            if args.is_docker:
                # find the bridge to snoop
                output = run_cmd(f"docker network inspect automation_{port}" +
                                 " -f '{{ index .IPAM.Config 0 \"Subnet\" }}'")
                baseip = re.sub(r"(\d+\.\d+\.\d+).*", r"\1", output)
                bridge = run_cmd(f"ip addr | grep -B2 'inet {baseip}' | head -1 | " +
                                 " awk '//{sub(/:/,\"\",$2); print $2}'")
                self.port = bridge
            run_cmd(f"rm -f {self.pcapname}")
            cmd = f"/usr/bin/tshark {snaparg} -B 1 -i {self.port} -w {self.pcapname}"
        else:
            cmd = f"rm -f {self.pcapname} && /usr/bin/tshark {snaparg} --time-stamp-type adapter_unsynced -B 1 -i {self.port} -w {self.pcapname}"
        super(PCapServer, self).__init__(f"pcap-server-{port}", host, cmd)

    def wait_up(self, upwait=30):
        logger.debug(f"Waiting for {self.name} ({self.port})")
        endtime = datetime.datetime.now() + datetime.timedelta(upwait)
        while datetime.datetime.now() < endtime:
            self.check_process()
            with open(self.output_filename, "r") as f:
                output = f.read()
            if re.search(f"Capturing on '{self.port}'", output):
                return True
            time.sleep(.1)
        raise Exception(f"{self.name} not up after {upwait} seconds")

    def count_drops(self):
        assert self.process is None or self.process.poll() is not None

        drops = 0
        m = re.search("ISB_IFDROP: ([0-9]+)", self.output)
        if m:
            drops += int(m.group(1))
        # Need to figure out what this value is.
        # The manpage is very vague
        m = re.search("ISB_OSDROP: ([0-9]+)", self.output)
        if m:
            drops += int(m.group(1))
        if drops:
            return drops

        # Normal Stderr (only available with local run not remote)
        m = re.search("([0-9]+) packets? dropped", self.output)
        if m:
            return int(m.group(1))
        return 0

    def count_captured(self):
        assert self.process is None or self.process.poll() is not None

        m = re.search("ISB_USRDELIV: ([0-9]+)", self.output)
        if m:
            return int(m.group(1))
        m = re.search("ISB_FILTERACCEPT: ([0-9]+)", self.output)
        if m:
            return int(m.group(1))
        m = re.search("ISB_IFRECV: ([0-9]+)", self.output)
        if m:
            return int(m.group(1))

        # Normal Stderr (only available with local run not remote)
        m = re.search("([0-9]+) packets? captured", self.output)
        if m:
            return int(m.group(1))
        return 0

    def stop(self):
        if self.process:
            self.process.terminate()

    def close(self):
        # if self.process:
        #     print("sending sigint to tshark")
        #     self.process.send_signal(signal.SIGHUP)
        #     time.sleep(2)
        super(PCapServer, self).close()
        time.sleep(.5)

        # Get info while still uncompressed
        pcap_info_path = f"{g_vpp_srcdir}/automation/pcap-info.sh"
        if self.host:
            pcap_info = self.remote_cmd(f"{pcap_info_path} {self.pcapname}")
        else:
            pcap_info = run_cmd(f"{pcap_info_path} {self.pcapname}")

        # Append pcap info to the log for this PCAP server
        if pcap_info:
            with open(self.output_filename, "a") as f:
                f.write("\n" + pcap_info)
            self.output += pcap_info

        prefix = f"CAPINFO: {self.name}: "
        logger.debug("%s", f"{prefix}{pcap_info}".replace("\n", "\n" + prefix))

        newname = f"{self.name}.pcap"
        if self.host:
            logger.debug(f"copying {self.pcapname} from {self.host}")
            run_cmd(f"rsync -zq {self.host}:{self.pcapname} {newname}")
            # For some reason running gzip on remote is hanging.
        else:
            run_cmd(f"mv {self.pcapname} {newname}")
        run_cmd(f"gzip {newname}")
        output = run_cmd(f"capinfos {newname}.gz")

        # Get this info from capinfos
        drops = self.count_drops()
        captures = self.count_captured()
        if drops:
            logger.warning(f"{self.name} with {captures} captures, {drops} drops")
        else:
            logger.info(f"{self.name} with {captures} captures")

    # def compress(self):
    #     assert self.process is None or self.process.poll() is not None
    #     logger.info(f"{self.name} compressing {self.pcapname}")
    #     self.remote_cmd(f"gzip {self.pcapname}")


class Bridge(Process):
    def __init__(self, args):
        """Create an Bridge in docker"""
        host = "brhost"
        self.args = args
        self.tempdir = tempfile.TemporaryDirectory(prefix="bridge-{host}")
        if self.args.live:
            cmd = "while true; do sleep 10; done"
        else:
            assert args.is_docker
            run_args = []
            if args.add_delay:
                run_args.append(f"-d {args.add_delay}")
            if args.add_loss:
                run_args.append(f"-l {args.add_loss}")
            if args.rate_limit:
                run_args.append(f"-r {args.rate_limit}")
            if args.testbed in testbed_docker_physical:
                run_args.append("-Y")
            run_script = os.path.join(g_vpp_srcdir, "automation/runbrhost.sh")
            cmd = run_script + " " + " ".join(run_args)
        super(Bridge, self).__init__("bridge", host, cmd, "", is_docker=args.is_docker)


class IKE(Process):
    def __init__(self, host, args):
        """Create an IKE server on a remote machine"""
        self.args = args
        self.binonly = args.testbed in testbed_binonly
        self.tempdir = tempfile.TemporaryDirectory(prefix=f"swan-{host}-")
        self.vici_sockname = os.path.join(self.tempdir.name, "vici.sock")
        ssh_opts = f" -L {self.vici_sockname}:/var/run/charon.ctl "
        self.autodir = "/usr/automation" if self.binonly else os.path.join(
            g_vpp_srcdir, "automation")
        if self.args.live:
            cmd = "while true; do sleep 10; done"
        else:
            run_ike_args = ["-t knl"]
            if args.is_docker:
                run_ike_args.append("-C")
            if args.dont_use_tfs:
                run_ike_args.append("-N")
            if args.connections > 1:
                run_ike_args.append(f"-m {args.connections}")
            if args.null:
                run_ike_args.append("-n")
            if args.max_latency:
                run_ike_args.append(f"-l {args.max_latency}")
            if args.rate:
                run_ike_args.append(f"-r {args.rate}")
            if args.iptfs_packet_size:
                run_ike_args.append(f"-s {args.iptfs_packet_size}")

            run_ike_script = os.path.join(self.autodir, "runike.sh")
            cmd = run_ike_script + " " + " ".join(run_ike_args)
        super(IKE, self).__init__("ike", host, cmd, ssh_opts, is_docker=args.is_docker)

        if args.is_docker:
            self.swanctl_cmd = os.path.join(g_vpp_native_root, "sbin/swanctl")
        elif self.binonly:
            self.swanctl_cmd = "/usr/sbin/swanctl"
        else:
            self.swanctl_cmd = "LD_LIBRARY_PATH={g_vpp_native_root}/lib " + os.path.join(
                g_vpp_native_root, "sbin/swanctl")

    def wait_up(self, upwait=30):
        logger.debug(f"Waiting for IKE on {self.host}")
        upcmd = "--stats"
        for _ in range(0, upwait):
            self.check_process()
            status, output = self.swanctl_status(upcmd)
            if not status and re.search("loaded plugins:.*kernel-vpp.*socket-vpp.*", output):
                logger.debug(f"IKE swanctl: success output: \"{output}\"")
                break
            logger.debug(f"IKE swanctl: got status: {status} output: \"{output}\"")
            time.sleep(1)
        else:
            out, err = self.process.communicate()
            self.close()
            raise Exception(f'IKE not up on {self.host} after {upwait}: output: "{self.output}"')

    def swanctl(self, ctlcmd):
        # Some sort of permissions problem still even with socket having vpp group privs which our
        # ssh "port map" should be good for.
        #return run_cmd(f"{self.swanctl_cmd} {ctlcmd} --uri unix://{self.vici_sockname}")
        return self.remote_cmd(f"{self.swanctl_cmd} {ctlcmd}")

    def swanctl_status(self, ctlcmd):
        # Some sort of permissions problem still even with socket having vpp group privs which our
        # ssh "port map" should be good for.
        #return run_cmd_status(f"{self.swanctl_cmd} {ctlcmd} --uri unix://{self.vici_sockname}")
        return self.remote_cmd_status(f"{self.swanctl_cmd} {ctlcmd}")


class TrexServer(Process):
    def __init__(self, host, args, cfgfile="/etc/trex_cfg.yaml"):
        """Create a VPP on a remote machine"""
        self.live = args.live
        self.is_docker = args.is_docker
        if self.live:
            cmd = None
        else:
            # 30 day refresh
            # arprefresh = 60 * 60 * 24 * 30
            # # Never send gratuitous ARP
            # arprefresh = 0
            if self.is_docker:
                self.connect_host = "localhost"
                if args.testbed not in testbed_docker_physical:
                    cmd = f"/vpp/automation/runtrex.sh -CP"
                else:
                    # Just run it on the host.
                    cmd = os.path.join(g_vpp_srcdir, f"automation/runtrex.sh -CY -c 2")
                    self.is_docker = False
                    self.host = host = ""
            else:
                self.connect_host = host
                cmd = os.path.join(g_vpp_srcdir, "automation/runtrex.sh")
                # cmd += f" -v 7 -c 16"
                cmd += f" -c 12"
                # cmd = "cd /opt/trex/current"
                # cmd += f" && sudo ./t-rex-64 --cfg {cfgfile} -i"
                # cmd += f" -c 2 --no-termio --iom 0 --arp-refresh-period {arprefresh}"
            if args.etfs3:
                cmd += " -e"
            if args.ipv6_traffic:
                cmd += " -9"
            if args.native_devices:
                cmd += " -V"
            if self.is_docker:
                if args.testbed in testbed_docker_physical:
                    cmd = f"bash -c 'TESTBED={args.testbed} HOSTNAME={host} {cmd}'"

        super(TrexServer, self).__init__("trex", host, cmd, is_docker=self.is_docker)

    def get_read_only_command(self):
        cmd = "/opt/trex/current && ./trex-console -r"

    def wait_up(self, upwait=30):
        logger.debug("Waiting for Trex")
        if not self.live:
            # Wait for ports 4501 it's the last one up.
            self.check_process()
        self.check_port(self.connect_host, 4501, timeout=upwait)


class SshServer(Process):
    def __init__(self, host, listenip, listenport, args):
        """Create an ssh server on a remote machine"""
        self.host = host
        self.listenip = listenip
        self.listenport = listenport
        self.is_docker = args.is_docker

        #
        # Sigh. sshd ignores HUP so we must do some extra work
        # to clean up afterward. Wrapper deals with that.
        #
        cmd = os.path.join(g_vpp_srcdir, "automation/runsshd.sh")
        cmd += f" -i {listenip} -p {listenport}"
        logger.debug(f"starting sshd with cmd={cmd}")

        super(SshServer, self).__init__("sshd", host, cmd, is_docker=args.is_docker)

    def wait_up(self, upwait=30, connect_timeout=4):
        logger.debug("Waiting for sshd")
        self.check_process()

        cmd = f"ssh -q -tt"
        cmd += f" -p {self.listenport}"
        cmd += f" -o ConnectTimeout={connect_timeout}"
        cmd += f" -o StrictHostKeyChecking=no"
        cmd += f" {self.listenip} echo foo"

        enter = datetime.datetime.now()
        while True:
            status, output = remote_cmd_status(self.host, cmd)
            if not status:
                logger.debug("sshd status is good")
                return True
            if (datetime.datetime.now() - enter).total_seconds() > upwait:
                raise Exception("waiting for sshd status timed out")
        return False


class VPP(Process):
    tun_stats_regex = r"/UNSET"
    error_regex = r"/err"

    def __init__(self, host, args, ordinal=0):
        """Create a VPP on a remote machine"""
        self.args = args
        self.tempdir = tempfile.TemporaryDirectory(prefix=f"vpp-{host}-")
        self.cli_sockname = os.path.join(self.tempdir.name, "cli.sock")
        self.api_sockname = os.path.join(self.tempdir.name, "api.sock")
        self.binonly = args.testbed in testbed_binonly
        self.autodir = "/usr/automation" if self.binonly else os.path.join(
            g_vpp_srcdir, "automation")
        ssh_opts = f" -L {self.cli_sockname}:/run/vpp/cli.sock "

        # if host == "m1":
        #     pdb.set_trace()

        # Default user ifindex is 1
        self.USER_IFINDEX = 1

        # 20.01 changed
        if g_vpp_maj_version < 20:
            api_sock = "vpp-api.sock"
        else:
            api_sock = "vpp/api.sock"

        ssh_opts += f" -L {self.api_sockname}:/run/{api_sock} "

        # datetime
        self.launch_time = datetime.datetime.now()

        self.is_docker = args.is_docker

        self.iptfs_enabled = True

        self.integrity_ipaddr = None
        self.integrity_ipaddr_base = None
        self.integrity_hostpart = None
        self.integrity_portnumber = None

        self.ordinal = ordinal

        cmd = self.get_cmd(args, host)

        super(VPP, self).__init__("vpp", host, cmd, ssh_opts, is_docker=args.is_docker)

        self.use_ike = bool(args.ike)
        self.ike = None

        self.node_names = {}
        self.node_stats = {}
        """Per-node (index) statistics (sum of all threads)"""
        self.thread_node_stats = {}
        """Per-thread (index) per-node (index) statistics"""

        self.ifnames = {}
        self.intf = {}
        self.intf_by_index = {}

        self.intf_stat_combined = {}
        self.intf_stat_counters = {}
        self.intf_stat_pkts = {}
        self.intf_stat_octets = {}

        self.intf_stat_combined_i = {}
        self.intf_stat_counters_i = {}
        self.intf_stat_pkts_i = {}
        self.intf_stat_octets_i = {}

        self.cleared_error_stats = {}

        self.client = None
        self.api = None
        self.event_log_saves = 0
        self.stats_shell = None
        self.shell_cmd = self.get_host_cmd_string("/bin/bash --noediting")

        if self.is_docker:
            self.api_sockname = f"/tmp/vpp-run-{self.host}/{api_sock}"
            self.vppctl_cmd = os.path.join(g_vpp_native_root, "bin/vppctl")
            self.vppctl_cmd = self.docker_exec + " " + self.vppctl_cmd
            self.vpp_get_stats_cmd = os.path.join(g_vpp_native_root, "bin/vpp_get_stats")
            api_dir = os.path.join(g_vpp_native_root, "share/vpp/api")
            self.shell_cmd = f"{self.docker_exec_tty} bash --noediting"
        elif self.binonly:
            # XXX does this work it used to use the temp sockname
            self.vppctl_cmd = "/usr/bin/vppctl"
            self.vpp_get_stats_cmd = "/usr/bin/vpp_get_stats"
            api_dir = os.path.join(self.tempdir.name, "api-files")
            logger.debug(f"Fetching API files from {self.host}")
            run_cmd(f"rsync -a {self.host}:/usr/share/vpp/api/ {api_dir}")
        else:
            self.vppctl_cmd = os.path.join(g_vpp_native_root, "bin/vppctl")
            self.vppctl_cmd += f" -s {self.cli_sockname}"
            self.vpp_get_stats_cmd = "sudo " + os.path.join(g_vpp_native_root, "bin/vpp_get_stats")
            api_dir = os.path.join(g_vpp_native_root, "share/vpp/api")

        self.api_files = VPPApiJSONFiles.find_api_files(api_dir)

    def get_tfs_args(self, args, remove):
        run_tfs_args = []
        self.iptfs_enabled = True
        if args.half_tfs:
            assert not args.dont_use_tfs
            assert not args.dont_use_ipsec
            assert not args.forward_only
            # For half set second to not use TFS
            if self.ordinal:
                run_tfs_args.append("-N")
                self.iptfs_enabled = False
        if args.cc:
            run_tfs_args.append(f"-a")
        if args.connections > 1:
            run_tfs_args.append(f"-m {args.connections}")
        if args.dont_use_ipsec:
            run_tfs_args.append("-O")
            self.iptfs_enabled = False
        if args.dont_use_tfs:
            run_tfs_args.append("-N")
            self.iptfs_enabled = False
        if args.encap_ipv6:
            run_tfs_args.append("-6")
        if args.encap_udp:
            run_tfs_args.append("-U")
        if args.etfs3:
            run_tfs_args.append("-x")
            self.iptfs_enabled = False
        if args.forward_only:
            run_tfs_args.append("-F")
            self.iptfs_enabled = False
        if args.iptfs_packet_size:
            run_tfs_args.append(f"-s {args.iptfs_packet_size}")
        if args.ipv6_traffic:
            run_tfs_args.append("-9")
        if args.null:
            run_tfs_args.append("-n")
        if args.chaining:
            run_tfs_args.append("-c")
        if args.max_latency:
            run_tfs_args.append(f"-l {args.max_latency}")
        if args.no_pad_only:
            run_tfs_args.append("-P")
        if args.rate:
            run_tfs_args.append(f"-r {args.rate}")
        if args.tfs_mode:
            run_tfs_args.append(f"-M {args.tfs_mode}")
        if args.use_macsec:
            run_tfs_args.append("-k")
        if args.use_policy:
            run_tfs_args.append("-p")
        if args.native_devices:
            if "-V" not in run_tfs_args:
                run_tfs_args.append("-V")
        if remove:
            self.iptfs_enabled = False
            run_tfs_args.append("-R")
        return run_tfs_args

    def apply_config(self, config, fail_ok=False):
        try:
            config = config.split("\n")
        except AttributeError:
            pass
        for line in config:
            line = line.strip()
            if not line:
                continue
            # logger.debug("%s", f"{self.host}: APPLY: '{line}'")
            if fail_ok:
                status, output = self.vppctl_status(line)
                if status:
                    logger.warning("%s", f"{self.host}: WARN: '{line}': {output}")
                elif output.strip():
                    logger.debug("%s", f"{self.host}: INFO: '{line}': {output.strip()}")
            else:
                output = self.vppctl(line)
                if output.strip():
                    logger.debug("%s", f"{self.host}: INFO: '{line}': {output.strip()}")

    def add_tfs_config(self, args, fail_ok=False):
        logger.debug("%s", f"{self.host}: add tfs config")
        run_tfs_args = self.get_tfs_args(args, False)
        cmd = os.path.join(self.autodir, "gen-tfs-cfg.sh") + " " + " ".join(run_tfs_args)
        config, _ = self.remote_cmd_error(cmd)
        self.apply_config(config, fail_ok)

    def remove_tfs_config(self, args, fail_ok=False):
        logger.debug("%s", f"{self.host}: remove tfs config")
        run_tfs_args = self.get_tfs_args(args, True)
        cmd = os.path.join(self.autodir, "gen-tfs-cfg.sh") + " " + " ".join(run_tfs_args)
        config, _ = self.remote_cmd_error(cmd)
        self.apply_config(config, fail_ok)

    def get_cmd(self, args, host):
        self.iptfs_enabled = True
        if args.live:
            return "while true; do sleep 10; done"

        run_tfs_args = ["-H", host] if self.binonly else []
        workers = 5 if args.workers is None else args.workers
        init_skip = args.initial_cpu_skip

        if args.is_docker and self.ordinal:
            init_skip += 1 + int(workers)
        if init_skip:
            run_tfs_args.append(f"-S{init_skip}")

        if args.is_docker:
            run_tfs_args.append("-CE")

        run_tfs_args.append(f"-i -w {workers}")

        if not self.ordinal:
            run_tfs_args.append(f"-A")
        if args.buffers_per_numa:
            run_tfs_args.append(f"-b {args.buffers_per_numa}")
        if args.buffer_size:
            run_tfs_args.append(f"-B {args.buffer_size}")
        if args.native_devices:
            run_tfs_args.append("-V")
        if args.gdb:
            run_tfs_args.append("-G")
        if args.ike:
            run_tfs_args.append("-I")
        if args.integrity:
            self.integrity_ipaddr_base = "192.168.253"
            self.integrity_hostpart = self.ordinal + 1
            self.integrity_ipaddr = f"{self.integrity_ipaddr_base}.{self.integrity_hostpart}"
            self.integrity_portnumber = 10873
            run_tfs_args.append(f"-J {self.integrity_ipaddr}:{self.integrity_portnumber}")
        if args.async_crypto:
            run_tfs_args.append("-z")
        if args.native_crypto:
            run_tfs_args.append("-K")
        if args.mixed_crypto:
            run_tfs_args.append("-Z")
        if args.event_log_size:
            run_tfs_args.append(f"-e {args.event_log_size}")
        if args.rx_tfs_queues:
            run_tfs_args.append(f"-Q {args.rx_tfs_queues}")
        if args.rx_user_queues:
            run_tfs_args.append(f"-q {args.rx_user_queues}")
        if args.trace_frame_queue:
            run_tfs_args.append(f"-T {args.trace_frame_queue}")
        if args.trace_count:
            run_tfs_args.append(f"-t {args.trace_count}")
        if args.worker_ranges:
            run_tfs_args.append(f"-W {args.worker_ranges}")
        if args.worker_rx_starts:
            run_tfs_args.append(f"-R {args.worker_rx_starts}")
        if args.node_stats:
            run_tfs_args.append("-y")
        if args.testbed in testbed_docker_physical:
            run_tfs_args.append("-Y")

        run_tfs_args.extend(self.get_tfs_args(args, False))
        return os.path.join(self.autodir, "runtfs.sh") + " " + " ".join(run_tfs_args)

    def run_stats_cmd(self, cmd, shell=None):
        if not shell:
            if not self.stats_shell:
                self.stats_shell = self.get_shell("-stats")
            shell = self.stats_shell
        return self.remote_shell_cmd(cmd, shell)

    def memif_apply_startup_config(self):
        """Used to apply startup config when memif interfaces are in use"""
        logger.debug("Applying startup config")
        conf = self.remote_cmd("cat /tmp/vpp-startup-.conf")
        for line in conf.split("\n"):
            if not line:
                continue
            status, output = self.vppctl_status(f"{line}")
            if status:
                logger.warning(f"got status {status} from \"{line}\" output: \"{output}\"")
            elif output:
                logger.debug(f"got output from \"{line}\" output: \"{output}\"")
            elif "interface memif" in line:
                # We need to wait for the memif interface.
                match = re.match("create interface memif id ([0-9]+) socket-id ([0-9]+) .*", line)
                assert match
                memif_id = match.group(1)
                memif_sock_id = match.group(2)
                memif = f"memif{memif_sock_id}/{memif_id}"
                for i in range(16):
                    status, output = self.vppctl_status(f"show {memif}")
                    if status:
                        logger.debug(f"Waiting for {memif}")
                        time.sleep(1)
                    else:
                        break
                else:
                    logger.warning(f"{memif} never present")

    def wait_up(self, upwait=None):
        """Wait for initial config to apply"""
        if upwait is None:
            upwait = 120 if self.args.gdb else 30

        if self.is_docker:
            # Wait for the interfaces which is really just waiting for the socket too
            # before applying the config
            for i in range(0, 2):
                intf = testbed_interfaces[f"{self.host}-{i}"]
                now = datetime.datetime.now()
                self._wait_up(f"show int {intf}", intf, upwait)
                upwait -= (datetime.datetime.now() - now).seconds
                if upwait < 0:
                    upwait = 0
            self.memif_apply_startup_config()

        logger.debug("Waiting for initial config to apply")
        self._wait_up("show int loop0", "loop0.*up", upwait)

        #
        # Connect to the API
        #
        self.client = VPPApiClient(apifiles=self.api_files,
                                   use_socket=True,
                                   server_address=self.api_sockname)
        self.client.connect("run-tests")
        self.api = self.client.api

        #
        # Get the current interfaces
        #
        self.intf = {}
        self.intf_by_index = {}
        self.refresh_interfaces()

    def _wait_up(self, upcmd, upoutput, upwait=30):
        """Connect up the CLI and API and get interface info"""
        #
        # Wait for the CLI
        #
        logger.debug(f"Waiting for \"{upoutput}\" from \"{upcmd}\" on {self.host}")
        for _ in range(0, upwait):
            self.check_process()
            status, output = self.vppctl_status(upcmd)
            if not status and re.search(upoutput, output):
                break
            logger.debug(f"Missed in \"{upoutput}\" in \"{self.output}\" status: {status}")
            time.sleep(1)
        else:
            status, output = self.vppctl_status("show log")
            raise Exception(
                f"VPP not up on {self.host} after {upwait}" +
                " make sure you have permissions on the remote socket" +
                f' (member of group vpp?):\noutput: "{self.output}\nshow log: {output}"')

        # logger.debug(f"Got \"{upoutput}\" in \"{output}\"")

    def start_gather_stats_proc(self, gather_stats, gather_interval=1.0):
        f = open(f"vpp-stats-{self.host}.json", "w")

        gather_stats_shell = self.get_shell(suffix="-gather")

        def gather_thread():
            while True:
                try:
                    stats_string = self.remote_shell_cmd(
                        f"{self.vpp_get_stats_cmd} summary dump-machine '{gather_stats}'",
                        shell=gather_stats_shell)
                    stats = VPP.get_stats_from_string(stats_string, True)
                    time.sleep(gather_interval)
                    json.dump(stats, f)
                    f.flush()
                except subprocess.CalledProcessError:
                    time.sleep(.1)

        x = threading.Thread(target=gather_thread, args=())
        x.daemon = True
        x.start()

    def start_gather_fast_stat_proc(self, gather_stat, gather_index=None, gather_interval=1.0):
        """Start a fast stat gather thread for a single stat"""
        f = open(f"vpp-fast-stat-{self.host}.csv", "w")

        stats_shell = self.get_shell(suffix="-gather-fast")

        def gather_thread():
            only_index = f"only-index {gather_index}" if gather_index is not None else ""
            stats_string = self.remote_shell_cmd(
                f"{self.vpp_get_stats_cmd} timestamp summary " +
                f"interval {gather_interval} machine {only_index} " + f"poll '{gather_stat}'",
                shell=stats_shell,
                no_capture=True)
            timestamp = None
            while True:
                try:
                    stats_shell.expect("\n")
                    stat = stats_shell.before.decode()
                    if self.shell_prompt in stat:
                        e = "ERROR: Fast gather poller exited"
                        logging.error("%s", e)
                        raise Exception(e)
                    # logging.info("STAT: %s", stat)
                    stats = VPP.get_fast_stat_from_string(stat, True, timestamp)
                    if stats is None:
                        continue
                    if timestamp is None:
                        timestamp = float(stats[1])
                        stats = (stats[0], "0", *stats[2:])
                    f.write("\t".join(stats[1:]) + "\n")
                    f.flush()
                except pexpect.TIMEOUT:
                    logging.error("ERROR: Timeout in gather fast stat thread")
                    raise

        x = threading.Thread(target=gather_thread, args=())
        x.daemon = True
        x.start()

    def gather_any_core_info(self):
        """Check for process exit and core"""
        if not self.process:
            return

        status = self.process.poll()

        if not status:
            return
        # Status must be negative (signal) for there to be a core
        if status < 127:
            return

        # Need the date/time of this launch.
        datestr = self.launch_time.strftime("%Y-%m-%d %H:%M:%S")
        cmd = f"sudo coredumpctl -q --since='{datestr}' --no-legend info vpp"
        if self.is_docker:
            status, output = run_cmd_status(cmd)
        else:
            status, output = self.remote_cmd_status(cmd)
        if not status and output:
            logger.error("CORE DETECTED:\n%s", output)

    def check_running(self):
        """Check the process actually is running"""
        try:
            self.api.control_ping()
        except VPPIOError:
            logger.warning("Got VPPIOError from calling VPP api")
            return False
        except Exception:
            logger.warning("Got generic exception from calling VPP api")
            return False
        return not self.process.poll()

    def vppctl(self, ctlcmd):
        if self.binonly:
            return self.remote_shell_cmd(f"{self.vppctl_cmd} {ctlcmd}")
        else:
            cmd = f"{self.vppctl_cmd} {ctlcmd}"
            logger.debug(f"running: {cmd}")
            return run_cmd(cmd)

    def vppctl_status(self, ctlcmd):
        if self.binonly:
            return self.remote_shell_cmd_status(f"{self.vppctl_cmd} {ctlcmd}")
        else:
            cmd = f"{self.vppctl_cmd} {ctlcmd}"
            logger.debug(f"running: {cmd}")
            return run_cmd_status(cmd)

    def get_event_log(self):
        rlogname = f"event-log-{os.environ['USER']}"
        self.vppctl(f"event-logger save {rlogname}")
        return self.remote_cmd(f"sudo cat /tmp/{rlogname}", encoding=None)

    def save_event_log(self):
        """Save the current event log into a file, increment logname counter"""
        rlogname = f"event-log-{os.environ['USER']}"
        llogname = f"{self.host}-events-{self.event_log_saves}.clib"
        output = self.vppctl(f"event-logger save {rlogname}").strip()
        if self.is_docker:
            run_cmd(f"docker cp {self.cont_id}:/tmp/{rlogname} {llogname}")
        else:
            run_cmd(f"rsync -q {self.host}:/tmp/{rlogname} {llogname}")
        logger.debug("%s", f"Saved event log in {llogname}: {output}")
        self.event_log_saves += 1

    def resize_event_log(self, size):
        return self.vppctl(f"event-logger resize {size}")

    @staticmethod
    def get_fast_stat_from_string(stat, summarized=False, ts_off=None):  # pylint: disable=R0911
        stat = stat.strip()
        if not stat:
            return None

        tsi = stat.find(":")
        if tsi == -1:
            return None
        if "." not in stat[:tsi]:
            timestamp = None
            stypei = tsi
        else:
            # logging.info(f"TS: {tsi} {stat}")
            timestamp = stat[:tsi]
            if ts_off is not None:
                timestamp = str(float(timestamp) - ts_off)
            stat = stat[tsi + 1:]
            stypei = stat.index(":")
        snamei = stat.rindex(":")
        stype = int(stat[:stypei])
        sname = stat[snamei + 1:]
        if stype == STYPE_NAME_VECTOR:
            return None

        svalues = stat[stypei + 1:snamei].split(":")
        if stype == STYPE_SCALAR_INDEX:
            # svalues: (floating point)
            return sname, timestamp, svalues[0]

        if stype == STYPE_ERROR_INDEX:
            # svalues: (thread, error counter)
            if summarized:
                return sname, svalues[0]
            return sname, timestamp, svalues[1]

        if stype == STYPE_COUNTER_VECTOR_SIMPLE:
            # svalues: (index, thread, counter)
            if summarized:
                index, counter = svalues
            else:
                index, counter = svalues[0], svalues[2]
            return sname, timestamp, index, counter

        if stype == STYPE_COUNTER_VECTOR_COMBINED:
            # svalues: (index, thread, pkt counter, byte counter)
            if summarized:
                index, npkts, noctets = svalues
            else:
                index, npkts, noctets = svalues[0], svalues[2], svalues[3]
            return sname, timestamp, index, npkts, noctets

        return None

    @staticmethod
    def get_stats_from_string(stats_string, summarized=False):
        indexes = {}
        names = {}
        scalars = {}
        errors = defaultdict(int)
        counters = defaultdict(lambda: defaultdict(int))
        pkts = defaultdict(lambda: defaultdict(int))
        octets = defaultdict(lambda: defaultdict(int))
        for stat in stats_string.split("\n"):
            if not stat:
                continue
            try:
                tsi = stat.index(":")
                if "." not in stat[:tsi]:
                    timestamp = None
                    stypei = tsi
                else:
                    logging.info("%s", f"TS: {tsi} {stat}")
                    timestamp = stat[:tsi]
                    stat = stat[tsi:]
                    stypei = stat.index(":")
            except:
                pdb.set_trace()
            stype = int(stat[:stypei])
            stat = stat[stypei + 1:]
            if stype == STYPE_NAME_VECTOR:
                # (index, name_for_index, stat name)
                index, stat = stat.split(":", 1)
                name, sname = stat.rsplit(":", 1)
                if sname not in indexes:
                    indexes[sname] = {}
                if sname not in names:
                    names[sname] = {}
                names[sname][int(index)] = name
                indexes[sname][name] = int(index)
            elif stype == STYPE_ERROR_INDEX:
                if summarized:
                    # (error counter, stat name)
                    evalue, sname = stat.split(":", 1)
                else:
                    # (thread, error counter, stat name)
                    _, evalue, sname = stat.split(":", 2)
                errors[sname] += int(evalue)
            elif stype == STYPE_SCALAR_INDEX:
                # svalues: (floating point, stat name)
                value, sname = stat.split(":", 1)
                scalars[sname] = float(value)
            elif stype == STYPE_COUNTER_VECTOR_SIMPLE:
                if summarized:
                    # (objindex, counter, stat name)
                    index, counter, sname = stat.split(":", 2)
                else:
                    # (objindex, thread, counter, stat name)
                    index, _, counter, sname = stat.split(":", 3)
                counters[int(index)][sname] += int(counter)
            elif stype == STYPE_COUNTER_VECTOR_COMBINED:
                if summarized:
                    # (objindex, pkt counter, byte counter)
                    index, npkts, noctets, sname = stat.split(":", 3)
                else:
                    # (objindex, thread, pkt counter, byte counter)
                    index, _, npkts, noctets, sname = stat.split(":", 4)
                pkts[int(index)][sname] += int(npkts)
                octets[int(index)][sname] += int(noctets)
        return counters, pkts, octets, errors, scalars, names, indexes

    def get_stats(self, regex):
        stats_string = self.run_stats_cmd(f"{self.vpp_get_stats_cmd} dump-machine '{regex}'")
        return VPP.get_stats_from_string(stats_string)

    def update_interface_counters(self):
        counters, pkts, octets, _, _, _, _ = self.get_stats("/if/.*")
        self.intf_stat_counters_i = counters
        self.intf_stat_pkts_i = pkts
        self.intf_stat_octets_i = octets
        for index in self.intf_by_index:
            ifname = self.ifnames[index]
            self.intf_stat_counters[ifname] = counters[index]
            self.intf_stat_pkts[ifname] = pkts[index]
            self.intf_stat_octets[ifname] = octets[index]
            self.intf_stat_combined[ifname] = {**pkts[index], **counters[index]}
            self.intf_stat_combined_i[index] = self.intf_stat_combined[ifname]

    def clear_interface_counters(self):
        self.api.sw_interface_clear_stats(sw_if_index=UINT_NULL)

    def refresh_interfaces(self):
        result = self.api.sw_interface_dump(sw_if_index=UINT_NULL)
        # [sw_interface_details(_0=86, context=1, sw_if_index=0, sup_sw_if_index=0, l2_address_length=0,  # pylint: disable=C0301
        # l2_address=b'\x00\x00\x00\x00\x00\x00\x00\x00', admin_up_down=0, link_up_down=0, link_duplex=0, link_speed=0,
        # link_mtu=0, mtu=[0, 0, 0, 0], sub_id=0, sub_dot1ad=0, sub_dot1ah=0, sub_number_of_tags=0, sub_outer_vlan_id=0,
        # sub_inner_vlan_id=0, sub_exact_match=0, sub_default=0, sub_outer_vlan_id_any=0, sub_inner_vlan_id_any=0,
        # vtr_op=0, vtr_push_dot1q=0, vtr_tag1=0, vtr_tag2=0, outer_tag=0, b_dmac=b'\x00\x00\x00\x00\x00\x00',
        # b_smac=b'\x00\x00\x00\x00\x00\x00', b_vlanid=0, i_sid=0, interface_name='local0', tag=''),
        user_interface_name = testbed_interfaces[self.host + "-0"]
        for details in result:
            if details.interface_name.lower() == user_interface_name.lower():
                self.USER_IFINDEX = details.sw_if_index
                logger.debug("%s", f"VPP {self.host} user_ifindex {self.USER_IFINDEX}")

            self.ifnames[details.sw_if_index] = details.interface_name
            self.intf_by_index[details.sw_if_index] = details
            self.intf[details.interface_name] = details

        self.update_interface_counters()

    def clear_error_stats(self):
        _, _, _, errors, _, _, _ = self.get_stats(self.error_regex)
        self.cleared_error_stats = errors

    def get_error_stats(self, non_zero_only=False):
        _, _, _, errors, _, _, _ = self.get_stats(self.error_regex)
        oerrors = self.cleared_error_stats
        for k in errors:
            if k in oerrors:
                errors[k] -= oerrors[k]

        if non_zero_only:
            return {k: v for k, v in errors.items() if v}
        return errors

    def get_tun_stats(self):
        counters, pkts, octets, _, _, _, _ = self.get_stats(self.tun_stats_regex)
        combined = {}
        indexes = counters.keys()
        for index in indexes:
            combined[index] = {**counters[index], **pkts[index]}

        return combined, counters, pkts, octets, self.get_error_stats()

    def clear_node_counters(self):
        """Clear node runtime statistics"""
        self.vppctl("clear runtime")
        self.vppctl("clear pmc")

    def get_node_stats(self, regex):  # pylint: disable=R0914
        stats_string = self.run_stats_cmd(f"{self.vpp_get_stats_cmd} dump-machine '{regex}'")
        # stats_string = self.remote_cmd(f"{self.vpp_get_stats_cmd} dump-machine '{regex}'")
        names = {}
        indexes = {}
        counters = {}
        try:
            for stat in stats_string.split("\n"):
                stypei = stat.index(":")
                snamei = stat.rindex(":")
                stype = int(stat[:stypei])
                sname = stat[snamei + 1:]
                if stype == STYPE_NAME_VECTOR:
                    if sname != "/sys/node/names":
                        continue
                    # svalues: (index, name_for_index)
                    # We need to split only once to miss any :'s in the name.
                    svalues = stat[stypei + 1:snamei].split(":", 1)
                    index = int(svalues[0])
                    name = svalues[1]
                    names[index] = name
                    indexes[name] = index
                else:
                    svalues = stat[stypei + 1:snamei].split(":")
                    if stype == STYPE_COUNTER_VECTOR_SIMPLE:
                        # svalues: (index, thread, counter)
                        index, thread, counter = (int(x) for x in svalues)
                        if thread not in counters:
                            counters[thread] = {}
                        if index not in counters[thread]:
                            counters[thread][index] = {}
                        counters[thread][index][sname] = counter
                    else:
                        assert False
            return counters, names
        except Exception as ex:
            print(ex)
            pdb.set_trace()
            raise

    def update_node_counters(self):
        """Updated node runtime statistics"""
        counters, names = self.get_node_stats("/sys/node/")
        self.node_names = names
        self.node_stats = {}
        self.thread_node_stats = {}
        for thread_index in counters:
            thread_counters = counters[thread_index]
            for node_index in thread_counters:
                node_counters = counters[thread_index][node_index]
                if not node_counters["/sys/node/calls"]:
                    continue
                if not node_counters["/sys/node/clocks"]:
                    continue
                # We care about anything that's wasting time I guess
                # if not node_counters["sys/node/vectors"]:
                #     continue
                clocks = node_counters["/sys/node/clocks"]
                calls = node_counters["/sys/node/calls"]
                packets = node_counters["/sys/node/vectors"]
                susp = node_counters["/sys/node/suspends"]
                per_call_clocks = clocks / calls
                per_call_pkts = packets / calls
                per_pkt_clocks = (clocks / packets) if packets else 0.0

                stats = NodeStats(names[node_index], calls, clocks, packets, susp, per_call_clocks,
                                  per_call_pkts, per_pkt_clocks)

                if thread_index not in self.thread_node_stats:
                    self.thread_node_stats[thread_index] = {}
                self.thread_node_stats[thread_index][node_index] = stats

                # if node_index not in self.node_stats:
                #     self.node_stats[node_index] = stats
                # else:
                #     old_stats = self.node_stats[node_index]
                #     per_call_clocks = (clocks + old_stats.clocks) / (calls + old_stats.clocks)
                #     divisor = packets + old_stats.packets
                #     per_pkt_clocks = (clocks + old_stats.clocks) / divisor if divisor else 0.0
                #     self.node_stats[node_index] = NodeStats(
                #         stats[0], *map(sum, zip(old_stats[node_index][1:5], stats[1:5])),
                #         per_call_clocks, per_pkt_clocks)


class IPTFSVPP(VPP):
    tun_stats_regex = r"/net/ipsec/sa/iptfs"
    error_regex = r"/err"

    def ike_up(self, upwait=30):
        if not self.use_ike:
            return
        if not self.ike:
            self.ike = IKE(self.host, self.args)
        self.ike.wait_up(upwait)
        if self.is_docker:
            output = self.ike.swanctl("--load-all --file /tmp/etc-swan/swanctl/swanctl.conf")
        else:
            output = self.ike.swanctl(
                f"--load-all --file /tmp/etc-swan-{os.environ['USER']}/swanctl/swanctl.conf")
        logger.debug("%s", f"{self.name}: ike --load-all output: {output}")

    def ike_initiate(self, child="vpp"):
        assert self.use_ike
        output = self.ike.swanctl(f"--initiate --child {child}")
        logger.debug("%s", f"{self.name}: ike --initiate --child output: {output}")

    def wait_tfs_up(self, initiate_child=None, upwait=30):
        if self.args.forward_only or self.args.dont_use_ipsec:
            return
        if self.use_ike:
            if initiate_child:
                self.ike_initiate(initiate_child)

        # XXX "1" is an VPP index that can be re-used
        upcmd = "show ipsec sa 1"
        if self.iptfs_enabled:
            upoutput = "tfs data: OUTBOUND:"
        else:
            upoutput = "protocol:esp"
        self._wait_up(upcmd, upoutput, upwait)


class ETFS3VPP(VPP):
    tun_stats_regex = r"/etfs3"
    error_regex = r"/err/etfs3"

    def wait_tfs_up(self, initiate_child=None, upwait=30):
        del initiate_child
        upcmd = "show etfs3 flow"
        upoutput = "Decap flow 0"
        self._wait_up(upcmd, upoutput, upwait)


@atexit.register
def cleanup():
    logger.debug("Cleaning up normal")
    while g_bg_procs:
        process = g_bg_procs.pop()
        if hasattr(process, "host"):
            process.close()
        else:
            logger.debug("%s", f"Terminating process: {process.args}")
            process.terminate()

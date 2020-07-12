# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# June 16 2020, Christian Hopps <chopps@labn.net>
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
import argparse
import atexit
import json
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
from traceback import print_exc

import autovpp.log
from autovpp import remote
from autovpp.tbdata import testbed_binonly
from autovpp.tbdata import testbed_docker
from autovpp.tbdata import testbed_servers
from autovpp.tbdata import testbed_trex
from autovpp.vpppath import g_vpp_ldpath, g_vpp_srcdir, g_vpp_native_root, g_def_logsdir
from autovpp.vpppath import g_trex_lib_dir
from autovpp.remote import PCapServer

from autovpp.tbdata import testbed_docker_physical

# Make sure we have extracted trex to use
if not os.path.exists(g_trex_lib_dir):
    remote.run_cmd(f"{g_vpp_srcdir}/automation/extract-trex.sh")


def exit_handler(signum, _):
    if signum in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
        logging.error("%s", f"Caught signal {signum} exiting cleanly")
        sys.exit(0)
    else:
        logging.error("%s", f"Caught signal {signum} exiting with code 1")
        sys.exit(1)


def int_or_intlist(nol):
    nol = nol.split(",")
    if len(nol) == 1:
        return int(nol[0])
    return [int(x) for x in nol]


def commalist(splitme):
    return splitme.split(",")


def convert_number(value):
    """Convert a number value with a possible suffix to an integer.

    >>> convert_number("100k") == 100 * 1024
    True
    >>> convert_number("100M") == 100 * 1000 * 1000
    True
    >>> convert_number("100Gi") == 100 * 1024 * 1024 * 1024
    True
    >>> convert_number("55") == 55
    True
    """
    if value is None:
        return None
    rate = str(value)
    base = 1000
    if rate[-1] == "i":
        base = 1024
        rate = rate[:-1]
    suffix = "KMGTPEZY"
    index = suffix.find(rate[-1])
    if index == -1:
        base = 1024
        index = suffix.lower().find(rate[-1])
    if index != -1:
        rate = rate[:-1]
    return int(rate) * base**(index + 1)


def options_to_prefix(args):
    prefix = f"{os.getenv('USER')}"
    prefix += f"-T={args.testbed}"
    prefix += f"-r={args.rate}"
    prefix += f"-l={args.max_latency}"
    prefix += f"-s={args.iptfs_packet_size}"
    if args.etfs3:
        prefix += "-etfs3"
    if args.null:
        prefix += "-null"
    if args.chaining:
        prefix += "-chain"
    if args.percentage:
        prefix += f"-p={args.percentage}"
    if args.duration:
        prefix += f"-d={args.duration}"
    if args.trace_count:
        prefix += f"-t={args.trace_count}"
    if args.user_packet_size:
        prefix += f"-U={args.user_packet_size}"

    for test in args.tests:
        test = test.replace(".py", "").replace("test_", "")
        prefix += f"-{test}"

    return prefix + "-"


def init_std_args():
    parser = argparse.ArgumentParser()
    runargs = parser.add_argument_group("run", "Execution Arguments")
    setupargs = parser.add_argument_group("setup", "Testbed Configuration")

    runargs.add_argument("--breakpoint", help="breakpoint to set if using gdb and tmux")
    setupargs.add_argument("-b",
                           "--buffers-per-numa",
                           type=convert_number,
                           default="0",
                           help="dpdk buffers-per-numa")
    setupargs.add_argument("-B",
                           "--buffer-size",
                           type=convert_number,
                           default="0",
                           help="buffer size")
    setupargs.add_argument("--cc", action="store_true", help="Use congestion control mode")
    setupargs.add_argument("--chaining",
                           action="store_true",
                           help="Use buffer copies instead of chaining")
    setupargs.add_argument("--copy", dest="chaining", action="store_false", help=argparse.SUPPRESS)
    runargs.add_argument("--capture-drops",
                         type=convert_number,
                         help="Number of drops to capture into pcap")
    runargs.add_argument(
        "-C",
        "--capture-ports",
        type=commalist,
        help="comma separated list of ports to capture on use host:port if remote.")
    runargs.add_argument(
        "--early-capture-ports",
        type=commalist,
        help="comma separated list of ports to capture early on use host:port if remote.")
    runargs.add_argument("--capture-snaplen",
                         type=convert_number,
                         help="snaplen for packet capture")
    runargs.add_argument("--connections", type=int, default=1, help="Number IPsec connections")
    runargs.add_argument("-d",
                         "--duration",
                         type=float,
                         default=10,
                         help="Duration for tests that support this parameter")
    runargs.add_argument("--dispatch-trace",
                         type=convert_number,
                         default="0",
                         help="Number of packets to dispatch trace into pcap file")
    setupargs.add_argument("-e", "--etfs3", default=False, action="store_true", help="Use ETFS3")
    runargs.add_argument("--encap-ipv6",
                         default=False,
                         action="store_true",
                         help="Use IPv6 for IPsec tunnel")
    runargs.add_argument("--encap-udp",
                         default=False,
                         action="store_true",
                         help="Use UDP for IPsec tunnel")
    setupargs.add_argument("--event-log-view",
                           default=False,
                           dest="view_event_logs",
                           action="store_true",
                           help="Don't clear event logs at start of test")
    setupargs.add_argument("--event-log-barrier",
                           action="store_true",
                           help="Enable barrier sync logs")
    setupargs.add_argument("--event-log-cpel",
                           action="store_true",
                           help="Convert event log clib to cpel format")
    setupargs.add_argument("--event-log-dispatch",
                           action="store_true",
                           help="Enable dispatch event logs -- includes barrier as well")
    setupargs.add_argument("--event-log-startup",
                           action="store_true",
                           help="Don't clear event logs at start of test")
    setupargs.add_argument("--event-log-size", help="View event logs")
    setupargs.add_argument("--forward-only",
                           action="store_true",
                           help="dont configure tunnel (ipip, ipsec or tfs)")
    runargs.add_argument("--gather-interval",
                         type=float,
                         default=1.0,
                         help="interval for gather stats")
    runargs.add_argument("--gather-fast-interval",
                         type=float,
                         default=0.1,
                         help="interval for gather fast stat")
    runargs.add_argument("--gather-fast-index", default=0, help="index of counter stat to gather")
    runargs.add_argument("--gather-fast-stat", help="regex of stat to gather at high rate to CSV")
    runargs.add_argument("--gather-stats", help="regex of stats to gather into file")
    runargs.add_argument("-g", "--gdb", action="store_true", help="Launch first VPP with gdbserver")
    setupargs.add_argument("--half-tfs",
                           default=False,
                           action="store_true",
                           help="Half-TFS/Half-IPsec")
    setupargs.add_argument("--impulses",
                           type=int_or_intlist,
                           help="number of impulses in test, or packeton,packetoff number pair")
    setupargs.add_argument("-I", "--ike", default=False, action="store_true", help="Use IKE")
    setupargs.add_argument("--integrity",
                           default=False,
                           action="store_true",
                           help="Run data integrity test")
    setupargs.add_argument("--initial-cpu-skip",
                           type=int,
                           default=0,
                           help="Initial skip core count, useful to move to isolcpus")
    setupargs.add_argument("--is-docker",
                           default=False,
                           action="store_true",
                           help=argparse.SUPPRESS)
    runargs.add_argument("--ipv6-traffic",
                         default=False,
                         action="store_true",
                         help="Use IPv6 for user traffic")
    setupargs.add_argument("-k", "--use-macsec", action="store_true", help="enable macsec for etfs")
    runargs.add_argument("--logsdir",
                         default=g_def_logsdir,
                         help="parent directory of runs log directory and files.")
    runargs.add_argument("--logdir", help="Directory to put logfiles i.e., don't use --logsdir")
    runargs.add_argument(
        "--log-replace",
        action="store_true",
        help="If run log directory (subdir of logsdir) should overwrite previous runs")
    setupargs.add_argument("-l",
                           "--max-latency",
                           type=convert_number,
                           default="10000",
                           help="Maximum latency (usec) for sending user traffic")
    setupargs.add_argument("-n", "--null", action="store_true", help="Use null encryption")
    setupargs.add_argument("-N", "--dont-use-tfs", action="store_true", help="dont configure tfs")
    setupargs.add_argument("--dont-use-ipsec",
                           action="store_true",
                           help="dont configure ipsec or tfs")
    setupargs.add_argument("--async-crypto",
                           action="store_true",
                           help="Use async crypto mode")
    setupargs.add_argument("--native-crypto",
                           action="store_true",
                           help="Use native crypto-engine instead of DPDK")
    setupargs.add_argument("--mixed-crypto",
                           action="store_true",
                           help="Use native crypto-engine on one VPP, DPDK on the other")
    setupargs.add_argument("--native-devices",
                           action="store_true",
                           help="Use native VPP devices instead of DPDK")
    runargs.add_argument("--old-imix",
                         default=False,
                         action="store_true",
                         help="Use older 7-4-1 IMix vs 50/50")
    setupargs.add_argument("--partial-drop-rate",
                           type=float,
                           help="allowable fractional percentage for NDR tests")
    setupargs.add_argument("-r",
                           "--rate",
                           type=convert_number,
                           default="10G",
                           help="Ethernet based rate")
    setupargs.add_argument("--rx-queues", type=int, help=argparse.SUPPRESS)
    setupargs.add_argument("--rx-user-queues", type=int, help="Number of user RX queues")
    setupargs.add_argument("--rx-tfs-queues", type=int, help="Number of TFS (tunnel) RX queues")
    setupargs.add_argument("--no-pad-only",
                           action="store_true",
                           help="Dont send all pads, useful for tracing")
    runargs.add_argument(
        "-p",
        "--percentage",
        type=float,
        default=None,
        help="percentage (float) of tunnel rate to send user traffic for tests that support this")
    runargs.add_argument("--pause",
                         action="store_true",
                         help="Pause at end of tests and on failures")
    runargs.add_argument("--pause-on-success",
                         action="store_true",
                         help="Pause at end of each test")
    setupargs.add_argument("-s",
                           "--iptfs-packet-size",
                           type=convert_number,
                           default="1500",
                           help="Ethernet based rate")
    setupargs.add_argument("--show-trex",
                           action="store_true",
                           help="Show trex summary in TMUX window")
    setupargs.add_argument("--tfs-mode",
                           help="TFS mode to run in (encap-only, min-rate, fixed-rate)")
    runargs.add_argument("-T",
                         "--testbed",
                         required=True,
                         help="testbed selection {}".format([x for x in testbed_servers]))  # pylint: disable=R1721
    setupargs.add_argument("-t",
                           "--trace-count",
                           type=convert_number,
                           default="0",
                           help="Number of initial packets to trace")
    setupargs.add_argument("--trace-frame-queue",
                           type=convert_number,
                           help="VPP frame queue to trace")
    runargs.add_argument("--add-delay",
                         type=convert_number,
                         help="Use bridge to add delay (usec) (only \"bridged\" docker for now)")
    runargs.add_argument("--add-loss",
                         help="Use bridge to add delay (0-100) (only \"bridged\" docker for now)")
    runargs.add_argument(
        "--rate-limit",
        type=convert_number,
        help="Use bridge to limit rate on tunnel link (only \"bridged\" docker for now)")
    setupargs.add_argument("--use-policy",
                           default=False,
                           action="store_true",
                           help="Use Policy vs Interface static config")
    setupargs.add_argument("-w", "--workers", type=convert_number, help="Number of workers to use")
    setupargs.add_argument("--worker-rx-starts",
                           help='rx placement starts for user and tfs "user-first,tfs-first"')
    setupargs.add_argument("--worker-ranges",
                           help='worker ranges "type=first:last[,type=first:last ...]')
    runargs.add_argument("--node-stats", action="store_true", help="Collect node statistics")
    runargs.add_argument("--live", action="store_true", help="Use already live running setup")
    runargs.add_argument("--unidirectional", action="store_true", help="Run test unidirectionally")
    runargs.add_argument("-U",
                         "--user-packet-size",
                         type=convert_number,
                         help="User packet size for tests that support this parameter")
    runargs.add_argument("-v", "--verbose", action="store_true", help="Verbose console messages")
    setupargs.add_argument("--view-event-logs", action="store_true", help=argparse.SUPPRESS)
    runargs.add_argument("tests", nargs="*", help="list of tests to run")
    return parser, runargs, setupargs


def finalize_args(args):
    if args.forward_only:
        args.dont_use_tfs = True
        args.dont_use_ipsec = True
    if args.rx_queues:
        assert not args.rx_user_queues and not args.rx_tfs_queues
        args.rx_user_queues = args.rx_queues
        args.rx_tfs_queues = args.rx_queues


def logdir_init_cd(args):
    if args.logdir:
        args.logdir = os.path.realpath(os.path.expanduser(args.logdir))

    if args.logsdir and args.logsdir != g_def_logsdir:
        args.logsdir = os.path.realpath(os.path.expanduser(args.logsdir))
        os.makedirs(args.logsdir, mode=0o755, exist_ok=True)
    os.makedirs(g_def_logsdir, mode=0o755, exist_ok=True)

    if args.log_replace:
        if not args.logdir:
            args.logdir = os.path.join(args.logsdir, options_to_prefix(args)[:-1])
        if os.path.exists(args.logdir):
            shutil.rmtree(args.logdir)
    elif not args.logdir:
        args.logdir = tempfile.mkdtemp(prefix=options_to_prefix(args), dir=args.logsdir)
    else:
        if os.path.exists(args.logdir):
            raise Exception(f"{args.logdir} exists and --log-replace not specified")
    os.makedirs(args.logdir, mode=0o755, exist_ok=True)

    # Create a symlink to our logdir
    remote.run_cmd(f"rm -f {g_def_logsdir}/latest; ln -f -s {args.logdir} {g_def_logsdir}/latest")

    autovpp.log.init(args)
    os.chdir(args.logdir)

    cmdline = " ".join(sys.argv)
    logging.info("%s", f"Command: {cmdline}")
    json.dump(vars(args), open("runtests-args.json", "w"))


def testbed_up(args):
    args.is_docker = args.testbed in testbed_docker
    binonly = args.testbed in testbed_binonly
    if binonly:
        # Need to transfer some automation files to the DUT.
        for server in testbed_servers[args.testbed]:
            remote.run_cmd(
                ("rsync -a --exclude='docker-trex-extract' --include='*/' --include='*.json'"
                 " --include='*.sh' --include='*.py' --exclude='*'"
                 f"{g_vpp_srcdir}/automation {server}:/usr"))
            remote.run_cmd(f"rsync -a /etc/vpp-lab-data/ {server}:/etc/vpp-lab-data/")

    # If this is the docker testbed, bring it u p.
    if args.is_docker:
        docker_up(args.testbed)


def docker_up(testbed):
    def cleanup():
        logging.debug("Cleaning up main")
        docker_down()

    atexit.register(cleanup)

    remote.run_cmd("sudo rm -rf /tmp/vpp-run-d[12]/")

    logging.info("Bringing up docker testbed")
    os.environ["VPPLDPATH"] = g_vpp_ldpath
    os.environ["VPPDIR"] = g_vpp_srcdir
    os.environ["VPPROOT"] = g_vpp_native_root
    os.environ["USERGID"] = str(os.getegid())
    os.environ["TESTBED"] = testbed

    # If this is a physical testbed we need to bind the interfaces now I think.
    if testbed in testbed_docker_physical:
        status, output = remote.run_cmd_status(f"{g_vpp_srcdir}/automation/setup-avf.sh")
        if status:
            raise Exception(f"setup-avf FAILED: {output}")
        status, output = remote.run_cmd_status("rm -f /tmp/vpp-run-shared/memif*")

    code, output = remote.run_cmd_status(
        f"envsubst < {g_vpp_srcdir}/automation/{testbed}-compose.yml.tpl " +
        f"> {g_vpp_srcdir}/automation/docker-compose.yml")
    code, output = remote.run_cmd_status(
        f"docker-compose -f {g_vpp_srcdir}/automation/docker-compose.yml up -d")
    if code:
        logging.critical("%s", f"docker-compose failed: {code}: {output}")
        sys.exit(1)

    time.sleep(5)


def docker_down():
    logging.info("Bringing down docker testbed")
    code, output = remote.run_cmd_status(
        f"docker-compose -f {g_vpp_srcdir}/automation/docker-compose.yml" +
        " down --timeout 1 --remove-orphans")
    if code:
        logging.error("%s", f"docker-compose down failed: {code}: {output}")


def vpps_up(args):
    vpplist = []
    logging.info("%s", f"Launching on testbed {args.testbed}")
    for i, name in enumerate(testbed_servers[args.testbed]):
        if not args.live:
            logging.debug("%s", f"Launching vpp on {name}")
        if args.etfs3:
            vpp = remote.ETFS3VPP(name, args, i)
        else:
            vpp = remote.IPTFSVPP(name, args, i)
        vpplist.append(vpp)

    # If there's a GDB server we need to connect to it.
    if args.gdb:
        bcmd = ""
        if "TMUX" not in os.environ:
            print('Execute the commands:')
        if args.gdb:
            if args.breakpoint:
                bcmd = f'-ex "b {args.breakpoint}"'
            for i, vpp in enumerate(vpplist):
                if args.is_docker:
                    rhost, rport = "localhost", 5010 + i + 1
                else:
                    rhost, rport = f"{vpp.host}", 5000

                if not remote.check_port(rhost, rport, 30):
                    print(f"Timeout waiting for GDB {rhost}:{rport}")
                    sys.exit(1)
                else:
                    time.sleep(.2)

                if args.testbed in testbed_binonly:
                    gdbcmd = ('gdb-multiarch /home/chopps/w-local/mb-build/openwrt/build_dir/'
                              'target-aarch64_cortex-a72_glibc/root-mvebu/usr/bin/vpp'
                              ' -ex "set breakpoint pending on" -ex "set pagination off"'
                              f' -ex "target remote {rhost}:{rport}" '
                              f' {bcmd} -ex "continue"')
                else:
                    gdbcmd = (f'gdb {g_vpp_native_root}/bin/vpp '
                              ' -ex "set breakpoint pending on" -ex "set pagination off"'
                              f' -ex "target remote {rhost}:{rport}" '
                              f' {bcmd} -ex "continue"')

                if "TMUX" in os.environ:
                    if i == 0:
                        tmuxcmd = f'tmux split-window -v {gdbcmd}'
                    else:
                        tmuxcmd = f'tmux split-window -h {gdbcmd}'
                    remote.run_bg_cmd(tmuxcmd)
                else:
                    print(f'  {gdbcmd}')
        # if "TMUX" in os.environ:
        #     remote.run_bg_cmd("tmux select-layout main-horizontal")
        if "TMUX" not in os.environ:
            input('Then ENTER here to continue.')
    return vpplist


def vpps_wait_up(args, vpplist):
    # Wait for servers to come up
    for vpp in vpplist:
        try:
            vpp.wait_up()
            vpp.clear_interface_counters()
            if args.gather_stats:
                vpp.start_gather_stats_proc(args.gather_stats, args.gather_interval)
            if args.gather_fast_stat:
                vpp.start_gather_fast_stat_proc(args.gather_fast_stat, args.gather_fast_index,
                                                args.gather_fast_interval)
        except Exception:
            vpp.gather_any_core_info()
            raise


def trex_up(args):
    # Bring up TREX
    if args.percentage == 0 or not args.tests or args.integrity:
        trex = None
    else:
        if args.etfs3:
            trex = remote.TrexServer(testbed_trex[args.testbed],
                                     args,
                                     cfgfile="/etc/trex_cfg-bridge.yaml")
        else:
            trex = remote.TrexServer(testbed_trex[args.testbed], args)
        trex.wait_up()
        if args.show_trex:
            tmuxcmd = 'tmux select-pane -t 1'
            remote.run_bg_cmd(tmuxcmd)
            assert "TMUX" in os.environ
            if trex.is_docker:
                cmd = trex.get_host_cmd_string("./trex-console -r")
            else:
                cmd = trex.get_host_cmd_string("cd /opt/trex/current && ./trex-console -r")
            tmuxcmd = f"tmux split-window -h {cmd}"
            remote.run_bg_cmd(tmuxcmd)
    return trex


def sshds_up(vpplist, args):
    sshdlist = []
    for vpp in vpplist:
        if not vpp.integrity_ipaddr:
            continue

        logging.info(f"starting ssh server on host {vpp.host}")
        sshd = remote.SshServer(vpp.host, vpp.integrity_ipaddr, vpp.integrity_portnumber, args)
        sshd.wait_up()
        sshdlist.append(sshd)

    return sshdlist


def vpps_ike_up(vpplist):
    for server in vpplist:
        try:
            server.ike_up()
        except Exception as ex:
            logging.warning("%s", f"Exception during IKE up on {server}: {ex}")
            print_exc()
            server.gather_any_core_info()
            raise


def vpps_tfs_up(vpplist):
    for i, server in enumerate(vpplist):
        try:
            for j in range(1, server.args.connections + 1):
                server.wait_tfs_up(initiate_child=f"vpp{j}" if i == 0 else None)
        except Exception as ex:
            logging.warning("%s", f"Exception during tfs up on {server}: {ex}")
            print_exc()
            server.gather_any_core_info()
            raise


def pcap_servers_up(args, capture_ports):
    capture_snaplen = args.capture_snaplen
    pcap_servers = []
    if capture_ports:
        if isinstance(capture_ports, str):
            capture_ports = [capture_ports]
        print(capture_ports)
        for port in capture_ports:
            s = port.split(":")
            if len(s) > 1:
                host, port = s
            else:
                host, port = None, s[0]
            pcap_servers.append(PCapServer(args, port, host, capture_snaplen))

        for pcap_server in pcap_servers:
            pcap_server.wait_up()
        # # Wait .1 second
        # time.sleep(.1)
    return pcap_servers


def init_all_up(args):
    testbed_up(args)

    # Start any early capture
    pcap_servers = pcap_servers_up(args, args.early_capture_ports)

    try:
        if args.testbed == "bridged":
            bridge = remote.Bridge(args)
        else:
            bridge = None

        vpplist = vpps_up(args)
        vpps_wait_up(args, vpplist)

        trex = trex_up(args)

        if not args.etfs3:
            vpps_ike_up(vpplist)
        vpps_tfs_up(vpplist)

        # sshd depends on veth interfaces created by the vpp etfs script
        sshdlist = sshds_up(vpplist, args)

        return vpplist, trex, [bridge, pcap_servers, sshdlist]
    except Exception:
        for server in pcap_servers:
            server.stop()
        for server in pcap_servers:
            server.close()
        raise


signal.signal(signal.SIGTERM, exit_handler)
signal.signal(signal.SIGQUIT, exit_handler)
signal.signal(signal.SIGHUP, exit_handler)
signal.signal(signal.SIGINT, exit_handler)

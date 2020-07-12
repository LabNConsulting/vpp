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
"""
A module of utility functions for authoring tests.
"""
from collections import defaultdict
import asyncio
import datetime
import json
import logging
import os
import pdb
import pprint
import re
import time

import autovpp.ndr as ndr
from autovpp.log import g_logdir
from .remote import run_cmd, IPTFSVPP
from .runlib import pcap_servers_up

logger = logging.getLogger(__name__)

UINT_NULL = 4294967295
USER_IFINDEX = 1


def get_human_readable(v):
    for suffix in ["", "K", "M", "G"]:
        if v < 1000.0:
            return "%3.03f%s" % (v, suffix)
        v /= 1000
    return "%3.1f%s" % (v, "T")


def line_rate_to_ip_pps(l1_rate, ipmtu):
    """Convert an L1 ethernet rate to number of IP packets of ipmtu size per second."""
    # Each IP packet requires 8b l1-preamble 14b l2-hdr 4b l2-crc and 12b l1-gap
    # The frame not including the preamble and inter frame gap must be at least 64b
    # 46b + 14 + 4 == 64
    emtu = 8 + max(64, 14 + ipmtu + 4) + 12
    return float(l1_rate) / (emtu * 8)


def ipsec_overhead(gcm, user_pkt_size=None, ipv6=False, udp=False):
    """Get the IPSEC payload size given a target IPTFS packet size"""
    # IPsec/ESP packets are aligned to 4 byte boundary.
    # target_mtu = target_mtu - (target_mtu % 4)
    if ipv6:
        # 40 - IP header, 8 ESP Header, 2 ESP Footer
        o = 40 + 8 + 2
    else:
        # 20 - IP header, 8 ESP Header, 2 ESP Footer
        o = 20 + 8 + 2
    if user_pkt_size:
        # User + Footer must align to 4 byte boundary
        over = (user_pkt_size + 2) % 4
        if over:
            o += 4 - over
    if udp:
        o += 8
    if gcm:
        o += 8 + 16  # IV + ICV = 1440
    return o


def iptfs_payload_size(target_mtu, gcm, cc=False, ipv6=False, udp=False):
    """Get the IPTFS payload size given a target IPTFS packet size"""
    # IPsec/ESP packets are aligned to 4 byte boundary.
    # target_mtu = target_mtu - (target_mtu % 4)
    assert (target_mtu % 4 == 0)
    iptfs_hdr_size = 4 if not cc else 24
    return target_mtu - ipsec_overhead(gcm, None, ipv6, udp) - iptfs_hdr_size


def iptfs_payload_rate(l1_rate, target_mtu, gcm, cc=False, ipv6=False, udp=False):
    ps = iptfs_payload_size(target_mtu, gcm, cc, ipv6, udp)
    return line_rate_to_ip_pps(l1_rate, target_mtu) * ps


def line_rate_to_iptfs_encap_pps(l1_rate, ipmtu, iptfs_mtu, gcm, cc=False, ipv6=False, udp=False):
    """Convert an l1 line rate to number of inner IP packets per second for a given
       IP MTU using (or not) GCM encryption
    """
    rate = iptfs_payload_rate(l1_rate, iptfs_mtu, gcm, cc, ipv6, udp)
    input_pps = rate / ipmtu
    return input_pps
    # XXX this max should be based on the *physical* line not on the rate we've
    # chosen.
    #max_pps = line_rate_to_ip_pps(l1_rate, ipmtu)
    #return min(max_pps, input_pps)


def line_rate_to_etfs_encap_pps(
        tunnel_line_rate,
        uf_ip_size,  # size of IP frame in user packets
        tunnel_etfs_mtu,  # size of ethernet payload (== etfs encap framesize)
        macsec_enabled):  # true/false

    uf_eth_size = uf_ip_size + 14

    #
    # Calculate ratio of user frames to tunnel frames. In ETFS
    # this number is not exact because fragments have a six-octet
    # header whereas full-frames have a two-octet header, but we
    # should be able to get reasonably close.
    #
    # Consider two cases (maybe they will reduce to the same formula):
    #
    # 1. Small user frames. Multiple full user frames fit into a
    #    single tunnel frame.
    #
    #    A full user frame takes up 2 + uf_eth_size, so the number
    #    of full frames that fit is:
    #
    #        NF = int(tunnel_etfs_mtu / (2 + uf_eth_size))
    #
    #    The remainder is likely to be filled with two fragments, one
    #    at the head of the tunnel frame and one at the tail. We assume
    #    a uniform distribution of head fragment lengths (i.e., there is
    #    an arbitrary shift of the contents with respect to the tunnel
    #    frame).
    #
    #    The number of actual full user frames in a tunnel packet will
    #    be either NF or NF-1, with a probability depending almost
    #    linearly on the size of the remainder. We will simplify for
    #    now and assume that if the remainder is greater than half the
    #    size of (UF+2), the actual number of full frames is NF, otherwise
    #    it will be NF-1.
    #
    #    The number of fragments will usually be two. I think the edge
    #    cases are improbable enough to ignore for this calculation.
    #
    # 2. Large user frames. Tunnel frames contain either one or two
    #    fragments. I think this case applies any time NF is 0.
    #

    NF = tunnel_etfs_mtu // (2 + uf_eth_size)

    if NF > 0:
        remainder = tunnel_etfs_mtu - (NF * (2 + uf_eth_size))
        if remainder > (2 + uf_eth_size) / 2:
            full_frame_count = NF
        else:
            full_frame_count = NF - 1

        full_frame_headers_per_tunnel_frame = NF
        fragment_headers_per_tunnel_frame = 2

    else:
        full_frame_headers_per_tunnel_frame = 0
        fragment_headers_per_tunnel_frame = 2

    payload = (tunnel_etfs_mtu - (2 * full_frame_headers_per_tunnel_frame) -
               (6 * fragment_headers_per_tunnel_frame))

    tunnel_packet_rate = line_rate_to_ip_pps(tunnel_line_rate, tunnel_etfs_mtu - 14)

    tunnel_payload_byte_rate = tunnel_packet_rate * payload

    payload_pps = tunnel_payload_byte_rate / uf_eth_size

    return payload_pps


def line_rate_to_pps(args, l1_rate, ipmtu, iptfs_mtu):
    """Convert an l1 line rate to number of packets per second for a given
       IP MTU using (or not) GCM encryption
    """

    gcm = not args.null
    if args.forward_only:
        pps = line_rate_to_ip_pps(l1_rate, ipmtu)
    elif args.dont_use_ipsec:
        ip_ohead = 20 if not args.encap_ipv6 else 40
        pps = line_rate_to_ip_pps(l1_rate, ipmtu + ip_ohead)
    elif args.dont_use_tfs:
        ipsec_ohead = ipsec_overhead(gcm, ipmtu, args.encap_ipv6, args.encap_udp)
        pps = line_rate_to_ip_pps(l1_rate, ipmtu + ipsec_ohead)
    else:
        pps = line_rate_to_iptfs_encap_pps(l1_rate, ipmtu, iptfs_mtu, gcm, args.cc, args.encap_ipv6,
                                           args.encap_udp)
    return pps


def get_max_client_rate(c):
    if not c:
        return None
    max_speed = 0
    ports = c.get_acquired_ports()
    if not ports:
        ports = [0, 1]
    for port in ports:
        stl_port = c.ports[port]
        info = stl_port.get_formatted_info()
        max_port_speed = max(info["supp_speeds"]) * 1000000
        if max_port_speed > max_speed:
            max_speed = max_port_speed
    return max_speed


def update_table_with_rate(args, imix_table, l1_rate, iptfs_mtu, percentage, normalize=False):
    def mps(x):
        return 46 if x < 46 else x

    pps_sum = sum([x["pps"] for x in imix_table])
    avg_ipsize = sum([mps(x["size"]) * x["pps"] for x in imix_table]) / pps_sum
    pps = line_rate_to_pps(args, l1_rate, avg_ipsize, iptfs_mtu)
    if percentage:
        pps *= percentage / 100

    if normalize:
        # Adjust the actual PPS to account for non-1 pps values in imix table,
        # Results for passing 1 as pps to trex start
        for x in imix_table:
            x["pps"] *= pps / pps_sum
    else:
        # Adjust the actual PPS to account for non-1 pps values in imix table
        # Results for passing pps as pps to trex start
        for x in imix_table:
            x["pps"] /= pps_sum

    return pps, avg_ipsize, pps_sum


def get_udp_spread_table(args, c):
    assert args.user_packet_size

    if args.ipv6_traffic:
        minpkt = 48
    else:
        minpkt = 28

    spread_count = (args.user_packet_size + 1) - minpkt
    avg_ipsize = sum(range(minpkt, args.user_packet_size + 1)) / spread_count
    pps = line_rate_to_pps(args, args.rate, avg_ipsize, args.iptfs_packet_size)
    if args.percentage:
        pps = pps * (args.percentage / 100)

    # if c:
    #     max_speed = get_max_client_rate(c)
    #     max_pps = line_rate_to_ip_pps(max_speed, avg_ipsize)
    #     if pps > max_pps:
    #         max_speed_float = max_speed / 1e9
    #         capacity = 100 * max_pps / pps
    #         logger.warning("%s", (f"Lowering pps from {pps} to {max_pps} due to client max speed"
    #                               f"{max_speed_float}GBps ({capacity:.1f}% of tunnel capacity)"))
    #         pps = max_pps

    table = [{
        'size': args.user_packet_size,
        'pps': pps,
        'pg_id': 1,
    }]
    desc = f"Spread (avg: {avg_ipsize}) @ {pps}pps for {args.duration}s"
    return table, pps, avg_ipsize, desc


def get_imix_table(args, c):
    if args.user_packet_size:
        ipsize = args.user_packet_size
        pps = line_rate_to_pps(args, args.rate, ipsize, args.iptfs_packet_size)
        if args.percentage:
            pps = pps * (args.percentage / 100)

        if c:
            max_speed = get_max_client_rate(c)
            max_pps = line_rate_to_ip_pps(max_speed, ipsize)
            if pps > max_pps:
                max_speed_float = max_speed / 1e9
                capacity = 100 * max_pps / pps
                logger.warning("%s",
                               (f"Lowering pps from {pps} to {max_pps} due to client max speed"
                                f"{max_speed_float}GBps ({capacity:.1f}% of tunnel capacity)"))
                pps = max_pps

        imix_table = [{
            'size': ipsize,
            'pps': pps,
            'pg_id': 1,
        }]
        desc = f"static IP size {ipsize}@{get_human_readable(pps)}pps"
        avg_ipsize = ipsize
    else:
        if args.old_imix:
            imix_table = [{
                'size': 40 if not args.ipv6_traffic else 60,
                'pps': 28,
                'isg': 0,
                'pg_id': 1,
            }, {
                'size': 576,
                'pps': 16,
                'isg': 0.1,
                'pg_id': 1,
            }, {
                'size': 1500,
                'pps': 4,
                'isg': 0.2,
                'pg_id': 1,
            }]
        else:
            imix_table = [{
                'size': 40 if not args.ipv6_traffic else 60,
                'pps': 50,
                'isg': 0,
                'pg_id': 1,
            }, {
                'size': 1500,
                'pps': 50,
                'isg': 0.1,
                'pg_id': 1,
            }]

        pps, avg_ipsize, _ = update_table_with_rate(args, imix_table, args.rate,
                                                    args.iptfs_packet_size, args.percentage, True)
        desc = f"imix (avg: {avg_ipsize})@{get_human_readable(pps)}pps"

    return imix_table, pps, avg_ipsize, desc


def clear_stats(c, vpplist, extended_stats, capture_drops=0, dispatch_trace=None):
    """Clear all statistics (and pcap drop capture if configured) in trex and vpp hosts"""
    if c is not None:
        c.clear_stats()
    for vpp in vpplist:
        if vpp.args.event_log_size and not vpp.args.event_log_startup:
            vpp.vppctl("event-logger stop")
            vpp.vppctl("event-logger clear")
        vpp.clear_interface_counters()
        vpp.clear_node_counters()
        vpp.vppctl("clear hardware-interfaces")
        vpp.vppctl("clear ipsec counters")
        vpp.vppctl("clear etfs3 counters")
        vpp.vppctl("clear iptfs counters")
        ifname = vpp.ifnames[vpp.USER_IFINDEX]
        if extended_stats:
            vpp.api.collect_detailed_interface_stats(sw_if_index=vpp.USER_IFINDEX, enable_disable=1)
        if capture_drops:
            vpp.remote_cmd("sudo rm -f /tmp/vpp-drops.pcap")
            vpp.vppctl(f"pcap trace drop max {capture_drops} intfc {ifname} file vpp-drops.pcap")
        if dispatch_trace:
            vpp.vppctl("pcap dispatch trace off")
            vpp.remote_cmd("sudo rm -f /tmp/dispatch.pcap")
            vpp.vppctl(f"pcap dispatch trace on max {dispatch_trace} file dispatch.pcap")
        vpp.vppctl("clear errors")
        vpp.clear_error_stats()


async def collect_vpp_stats(vpp, extended_stats):
    logger.debug("%s: Collecting stats", vpp.host)
    vpp.update_interface_counters()
    vlstats = {}
    for index, _ in enumerate(vpp.ifnames):
        vlstats[index] = vpp.intf_stat_combined_i[index]

    # Add ipsec/err stats to key "-1"
    vlstats[-1] = vpp.get_tun_stats()
    vlstats["errors"] = vpp.get_error_stats(non_zero_only=True)

    if extended_stats:
        vpp.api.collect_detailed_interface_stats(sw_if_index=vpp.USER_IFINDEX, enable_disable=0)

    return vlstats


def collect_trex_stats(args, c):
    stats = c.get_stats()
    stats[0]["rx-missed"] = stats[1]["opackets"] - stats[0]["ipackets"]
    stats[1]["rx-missed"] = stats[0]["opackets"] - stats[1]["ipackets"]
    if args.unidirectional:
        stats[0]["rx-missed-pct"] = 0
    else:
        stats[0]["rx-missed-pct"] = 100 * (stats[1]["opackets"] -
                                           stats[0]["ipackets"]) / stats[1]["opackets"]
    stats[1]["rx-missed-pct"] = 100 * (stats[0]["opackets"] -
                                       stats[1]["ipackets"]) / stats[0]["opackets"]
    return stats


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


def wait_for_test_done(vpplist, c, check_ports, starttime, endtime, beat_callback, beat_time=1):
    beat = datetime.timedelta(0, beat_time)
    nextbeat = starttime + beat

    count = 0
    while not c or c.is_traffic_active(ports=check_ports):
        # if c:
        #     logger.debug("active ports: %s acquired %s", str(c.get_active_ports()),
        #                  str(c.get_active_ports()))
        count += 1
        newnow = datetime.datetime.now()
        if newnow >= nextbeat:
            if beat_callback:
                beat_callback((newnow - starttime).total_seconds())
            newnow = datetime.datetime.now()
            nextbeat = nextbeat + beat
            if nextbeat < newnow:
                nextbeat = newnow + ((newnow - nextbeat) % beat)
                assert (nextbeat > newnow)

        # Need to make sure we don't abort b/c of gdb.
        if any([not x.args.gdb and not x.check_running() for x in vpplist]):
            logger.info("A VPP has exited")
            logger.info("Stopping traffic on TREX")
            if c:
                c.stop()
            break

        if newnow > endtime:
            # logger.warning("XXX: Past endtime %s", str(newnow - endtime))
            break

        sleeptime = min(1, (nextbeat - newnow).total_seconds())
        if not beat_callback:
            logger.debug("%s", f"Sleeping {sleeptime} seconds")
        time.sleep(sleeptime)

    if newnow < endtime:
        logger.warning("%s", f"TREX ended too early: {endtime - newnow}")
    else:
        logger.info("TREX: times up")

    if c:
        # Wait an additional 100ms for receiving sent traffic
        c.wait_on_traffic(rx_delay_ms=100)


async def run_trex_cont_test(args,
                             c,
                             vpplist,
                             mult,
                             get_streams_func,
                             imix_table,
                             extended_stats=False,
                             beat_callback=None,
                             beat_time=1,
                             modeclass=None,
                             statsclass=None):
    # create two streams
    mult = str(mult)
    duration = float(args.duration) if args.duration is not None else 10

    check_active_vpp(vpplist)

    if c:
        c.reset()  # Acquire port 0,1 for $USER

        ports = c.get_acquired_ports()
        assert (len(ports) == 2)

        check_ports = ports[:1] if args.unidirectional else ports
        # add both streams to ports
        for port in check_ports:
            extra_args = {}
            if args.connections > 1:
                extra_args["nstreams"] = args.connections
            c.add_streams(get_streams_func(port % 2,
                                           imix_table,
                                           modeclass=modeclass,
                                           statsclass=statsclass,
                                           ipv6=args.ipv6_traffic,
                                           **extra_args),
                          ports=port)

    # clear the stats before injecting
    clear_stats(None, vpplist, extended_stats, args.capture_drops,
                args.dispatch_trace if not c else None)

    # Try sending a short burst of the test to prime the pump.
    if c:
        if args.encap_ipv6:
            prime_duration = 1
        else:
            prime_duration = .1
        logger.info("Pre-starting TREX: to prime the pump: mult: %s duration: %s", str(mult),
                    str(prime_duration))
        c.start(ports=check_ports, mult=mult, duration=prime_duration)
        c.wait_on_traffic(rx_delay_ms=100)
        clear_stats(c, vpplist, extended_stats, args.capture_drops, args.dispatch_trace)

    # Start any capture
    pcap_servers = pcap_servers_up(args, args.capture_ports)

    for v in vpplist:
        if v.args.event_log_size and not v.args.event_log_startup:
            v.vppctl("event-logger restart")
            if v.args.event_log_dispatch:
                v.vppctl("elog trace api barrier dispatch")
            elif v.args.event_log_barrier:
                v.vppctl("elog trace api barrier ")

    #
    # Don't bother starting test if a VPP has exited.
    #
    check_active_vpp(vpplist)

    # Setup beat callback and end times
    starttime = datetime.datetime.now()
    endtime = starttime + datetime.timedelta(0, duration)

    #
    # Start the traffic
    #

    if c:
        logger.info("Starting TREX: mult: %s duration: %s", str(mult), str(duration))
        c.start(ports=check_ports, mult=mult, duration=duration)

    #
    # wait for active ports done
    #
    wait_for_test_done(vpplist, c, check_ports, starttime, endtime, beat_callback, beat_time)

    logger.debug("TREX: after wait on traffic")

    #
    # gpz workaround
    # ETFS tests have not waited long enough to collect VPP counters after
    # the test runs, causing reported values to be incorrect (low). Waiting
    # a few seconds here yields the correct values.
    #
    time.sleep(5)

    active_vpplist = get_active_vpp(vpplist)

    #
    # Stop event logs and captures.
    #
    cap_offs = {}
    dispatch_cap_offs = {}

    async def stop_disruptive(x):
        if x.args.dispatch_trace:
            dispatch_cap_offs[x.host] = x.vppctl("pcap dispatch trace off")
        if x.args.event_log_size:
            x.vppctl("event-logger stop")
        if args.capture_drops:
            cap_offs[x.host] = x.vppctl("pcap trace off")
        # Terminate the capture now.
        for server in pcap_servers:
            server.stop()

    await asyncio.gather(*[stop_disruptive(x) for x in active_vpplist])

    #
    # Get pcap captures
    #
    async def pcap_server_done(x):
        x.close()
        drops = x.count_drops()
        if drops:
            logger.warning("%s", f"{x.name} dropped {drops} packets")

    if pcap_servers:
        await asyncio.gather(*[pcap_server_done(server) for server in pcap_servers])

    active_vpplist = get_active_vpp(active_vpplist)

    #
    # Collect post run stats
    #

    stats = None
    if c:
        stats = collect_trex_stats(args, c)

    vstats = await asyncio.gather(
        *[collect_vpp_stats(vpp, extended_stats) for vpp in active_vpplist])

    active_vpplist = get_active_vpp(active_vpplist)

    #
    # Collect captures and logs that could be distruptive to stats.
    #

    logger.debug("Collecting disruptive stats")
    showrun = []
    for vpp in active_vpplist:
        sr = "RUN: " + vpp.vppctl("show runtime time").replace("\n", "\nRUN: ")
        sr += "\nMAX: " + vpp.vppctl("show runtime time max").replace("\n", "\nMAX: ")
        showrun.append(sr)

    pcap_files = {}
    dispatch_pcap_files = {}

    async def collect_disruptive(x):
        logger.debug("%s: Collecting disruptive stats", x.host)
        if x.host in cap_offs and "No packets" not in cap_offs[x.host]:
            # Grab the pcap file. XXX should go to file named for this test.
            pcap = x.get_remote_file("/tmp/vpp-drops.pcap")
            pcapfile = os.path.join(g_logdir, f"{x.host}-pcap-drop.pcap")
            with open(f"{pcapfile}", "wb") as pcapf:
                pcapf.write(pcap)
            pcap_files[x.host] = pcapfile
        if x.host in dispatch_cap_offs and "No packets" not in dispatch_cap_offs[x.host]:
            # Grab the pcap file. XXX should go to file named for this test.
            pcap = x.get_remote_file("/tmp/dispatch.pcap")
            pcapfile = os.path.join(g_logdir, f"{x.host}-pcap-dispatch.pcap")
            with open(f"{pcapfile}", "wb") as pcapf:
                pcapf.write(pcap)
            dispatch_pcap_files[x.host] = pcapfile
        if x.args.event_log_size:
            x.save_event_log()

    # for r in asyncio.as_completed([collect_disruptive(vpp) for vpp in vpplist]):
    #     await r

    results = []
    for vpp in active_vpplist:
        results.append(collect_disruptive(vpp))
    for result in results:
        await result

    #
    # Now that we've captured any packets and saved any event logs we safely raise an exception if
    # we had cores/exits
    #
    check_active_vpp(vpplist)

    #
    # Log show runtime
    #
    for i, sr in enumerate(showrun):
        name = vpplist[i].name
        logger.debug("%s:\n%s", name, sr.replace('\n', f"\n{name}: "))

    #
    # Print packet drops
    #

    for host, pcapfile in pcap_files.items():
        result = cap_offs[host]
        pcapfile = pcap_files[host]
        logger.warning("%s", f"Have some dropped packets to read {result}")
        logger.warning("%s", f"Decoding: {result}")
        logger.warning("%s", run_cmd(f"tcpdump -n -s9014 -vvv -ttttt -e -XX -r {pcapfile}"))

    return stats, vstats, pcap_servers


async def run_trex_ndr_test(args,
                            c,
                            vpplist,
                            get_streams_func,
                            extended_stats=False,
                            modeclass=None,
                            statsclass=None):

    if args.percentage is None:
        args.percentage = 100.0

    check_active_vpp(vpplist)

    def add_streams(client, rate):
        client.reset()  # Acquire port 0,1 for $USER
        ports = client.get_acquired_ports()
        assert (len(ports) == 2)
        check_ports = ports[:1] if args.unidirectional else ports

        orate = args.rate
        try:
            args.rate = rate
            it, pps, _, desc = get_imix_table(args, c)
        finally:
            args.rate = orate
        logger.debug("%s", f"Adding streams {desc}")

        # add both streams to ports
        for port in check_ports:
            extra_args = {}
            if args.connections > 1:
                extra_args["nstreams"] = args.connections
            client.add_streams(get_streams_func(port % 2,
                                                it,
                                                modeclass=modeclass,
                                                statsclass=statsclass,
                                                ipv6=args.ipv6_traffic,
                                                **extra_args),
                               ports=port)
        return check_ports, pps

    # clear the stats before injecting
    clear_stats(None, vpplist, extended_stats, args.capture_drops)

    for v in vpplist:
        if v.args.event_log_size and not v.args.event_log_startup:
            v.vppctl("event-logger restart")
            if v.args.event_log_dispatch:
                v.vppctl("elog trace api barrier dispatch")
            elif v.args.event_log_barrier:
                v.vppctl("elog trace api barrier ")

    #
    # Don't bother starting test if a VPP has exited.
    #
    check_active_vpp(vpplist)

    #
    # Start the traffic
    #
    logger.info("Starting TREX NDR")

    vars(args)["extended_stats"] = extended_stats
    ok_results, fail_results = await ndr.find_ndr(args, c, vpplist, add_streams)

    logger.debug("TREX: after find_ndr")

    check_active_vpp(vpplist)

    #
    # Stop event logs and captures.
    #
    async def stop_disruptive(x):
        if x.args.event_log_size:
            x.vppctl("event-logger stop")

    await asyncio.gather(*[stop_disruptive(x) for x in vpplist])

    active_vpplist = get_active_vpp(vpplist)

    #
    # Collect post run stats
    #

    if ok_results[0]:
        max_rx_pps, pct, drop0, drop1, stats, vstats = ok_results
        hrate = get_human_readable(pct * args.rate)
        rx_pps_human = get_human_readable(max_rx_pps)
        logging.info("%s", (f"NDR rate: TX {hrate}bps MAXRX: {rx_pps_human}pps:"
                            f" ({pct * args.rate} with drops {100*drop0}, {100*drop1})"))
    else:
        max_rx_pps, pct, drop0, drop1, stats, vstats = fail_results
        hrate = get_human_readable(pct * args.rate)
        rx_pps_human = get_human_readable(max_rx_pps)
        logging.info("%s", (f"NDR FAILED last rate: TX {hrate}bps MAXRX: {rx_pps_human}pps"
                            f" {pct * args.rate}: (drops {100*drop0}, {100*drop1})"))

    #
    # Collect captures and logs that could be distruptive to stats.
    #

    # logger.debug("Collecting disruptive stats")
    # showrun = []
    # for vpp in active_vpplist:
    #     sr = "RUN: " + vpp.vppctl("show runtime time").replace("\n", "\nRUN: ")
    #     sr += "\nMAX: " + vpp.vppctl("show runtime time max").replace("\n", "\nMAX: ")
    #     showrun.append(sr)

    async def collect_disruptive(x):
        logger.debug("%s: Collecting disruptive stats", x.host)
        if x.args.event_log_size:
            x.save_event_log()

    # for r in asyncio.as_completed([collect_disruptive(vpp) for vpp in vpplist]):
    #     await r

    results = []
    for vpp in active_vpplist:
        results.append(collect_disruptive(vpp))
    for result in results:
        await result

    #
    # Now that we've captured any packets and saved any event logs we safely raise an exception if
    # we had cores/exits
    #
    check_active_vpp(vpplist)

    # #
    # # Log show runtime
    # #
    # for i, sr in enumerate(showrun):
    #     name = vpplist[i].name
    #     logger.debug("%s:\n%s", name, sr.replace('\n', f"\n{name}: "))

    return stats, vstats, []


async def _run_trex_ndr_test(args,
                             c,
                             vpplist,
                             get_streams_func,
                             extended_stats=False,
                             modeclass=None,
                             statsclass=None):

    from trex.examples.stl import ndr_bench  # pylint: disable=C0415

    duration = float(args.duration) if args.duration is not None else 10
    configs = {
        'pdr': 0.1,
        # 'pdr': 0,
        'iteration_duration': duration,
        'ndr_results': 1,
        'first_run_duration': duration,
        'verbose': args.verbose,
        'pdr_error': 1.0,
        # 'pdr_error': 0.0,
        'title': "NDR Test",
        'ports': None,
        'q_full_resolution': 2.0,
        'max_iterations': 10,
        'max_latency': 0,
        'lat_tolerance': 0,
        'bi_dir': not args.unidirectional,
        # 'force_map_table': force_map_table,
        'plugin_file': None,
        'tunables': {},
        'max_rate_bps': args.rate,
        'opt_binary_search': False,
        'opt_binary_search_percentage': 5
    }

    trex_info = c.get_server_system_info()
    configs['cores'] = trex_info['dp_core_count_per_port']

    active_vpplist = get_active_vpp(vpplist)
    if active_vpplist != vpplist:
        for v in vpplist:
            if v not in active_vpplist:
                v.gather_any_core_info()
        raise Exception("Not all vpp are running")

    if c:
        c.reset()  # Acquire port 0,1 for $USER

        ports = c.get_acquired_ports()
        assert (len(ports) == 2)

        check_ports = ports[:1] if args.unidirectional else ports

        imix_table, _, _, _ = get_imix_table(args, c)

        # add both streams to ports
        for port in check_ports:
            extra_args = {}
            if args.connections > 1:
                extra_args["nstreams"] = args.connections
            c.add_streams(get_streams_func(port % 2,
                                           imix_table,
                                           modeclass=modeclass,
                                           statsclass=statsclass,
                                           ipv6=args.ipv6_traffic,
                                           **extra_args),
                          ports=port)
        configs['ports'] = check_ports

    # clear the stats before injecting
    clear_stats(None, vpplist, extended_stats, args.capture_drops)

    for v in vpplist:
        if v.args.event_log_size and not v.args.event_log_startup:
            v.vppctl("event-logger restart")
            if v.args.event_log_dispatch:
                v.vppctl("elog trace api barrier dispatch")
            elif v.args.event_log_barrier:
                v.vppctl("elog trace api barrier ")

    #
    # Don't bother starting test if a VPP has exited.
    #
    active_vpplist = get_active_vpp(vpplist)
    if active_vpplist != vpplist:
        for v in vpplist:
            if v not in active_vpplist:
                v.gather_any_core_info()
        raise Exception("Not all vpp are running")

    #
    # Start the traffic
    #
    logger.info("Starting TREX NDR")

    if c:
        config = ndr_bench.NdrBenchConfig(**configs)
        b = ndr_bench.NdrBench(stl_client=c, config=config)
        b.find_ndr()
        b.results.print_final()

    logger.debug("TREX: after find_ndr")

    active_vpplist = get_active_vpp(vpplist)

    #
    # Stop event logs and captures.
    #
    async def stop_disruptive(x):
        if x.args.event_log_size:
            x.vppctl("event-logger stop")

    await asyncio.gather(*[stop_disruptive(x) for x in active_vpplist])

    active_vpplist = get_active_vpp(active_vpplist)

    #
    # Collect post run stats
    #

    stats = None
    if c:
        result = {'results': b.results.stats, 'config': b.config.config_to_dict()}
        hu_dict = {'results': b.results.human_readable_dict(), 'config': b.config.config_to_dict()}
        stats = hu_dict

    async def collect_stats(x):
        logger.debug("%s: Collecting stats", x.host)
        x.update_interface_counters()
        vlstats = {}
        for index, _ in enumerate(x.ifnames):
            vlstats[index] = x.intf_stat_combined_i[index]

        # Add ipsec/err stats to key "-1"
        vlstats[-1] = x.get_tun_stats()

        if extended_stats:
            x.api.collect_detailed_interface_stats(sw_if_index=x.USER_IFINDEX, enable_disable=0)

        return vlstats

    vstats = await asyncio.gather(*[collect_stats(vpp) for vpp in active_vpplist])

    active_vpplist = get_active_vpp(active_vpplist)

    #
    # Collect captures and logs that could be distruptive to stats.
    #

    logger.debug("Collecting disruptive stats")
    showrun = []
    for vpp in active_vpplist:
        sr = "RUN: " + vpp.vppctl("show runtime time").replace("\n", "\nRUN: ")
        sr += "\nMAX: " + vpp.vppctl("show runtime time max").replace("\n", "\nMAX: ")
        showrun.append(sr)

    async def collect_disruptive(x):
        logger.debug("%s: Collecting disruptive stats", x.host)
        if x.args.event_log_size:
            x.save_event_log()

    # for r in asyncio.as_completed([collect_disruptive(vpp) for vpp in vpplist]):
    #     await r

    results = []
    for vpp in active_vpplist:
        results.append(collect_disruptive(vpp))
    for result in results:
        await result

    #
    # Now that we've captured any packets and saved any event logs we safely raise an exception if
    # we had cores/exits
    #
    active_vpplist = get_active_vpp(active_vpplist)
    if active_vpplist != vpplist:
        for v in vpplist:
            if v not in active_vpplist:
                v.gather_any_core_info()
        raise Exception("Not all vpp are running")

    #
    # Log show runtime
    #
    for i, sr in enumerate(showrun):
        name = vpplist[i].name
        logger.debug("%s:\n%s", name, sr.replace('\n', f"\n{name}: "))

    return stats, vstats, []


def save_stats(module_name, stats_name, stats):
    """Save stats to a json file.
    Pass in __name__ for module_name, a name for the stats,
    and the dictionary of stats, saves to a json file
    """
    with open(f"{stats_name}-{module_name.replace('.py', '')}.json", "w") as f:
        json.dump(stats, f)


def dump_ifstats_one(vpp, stats, ifindex=None):
    for lidx in range(0, len(vpp.ifnames)):
        if ifindex is not None and lidx != ifindex:
            continue
        ifname = vpp.ifnames[lidx]
        logger.info("%s", f"    Interface: {ifname}:")
        for key, count in stats[lidx].items():
            if not count:
                continue
            logger.info("%s", f"        {key}: {count} packets")


def dump_ifstats(vpplist, vstats, ifindex=None):
    for index, vpp in enumerate(vpplist):
        logger.info("%s", f"{vpp.host}:")
        dump_ifstats_one(vpp, vstats[index], ifindex)


def dump_tun_stats(vpp, counters, pkts, octets, errors, counter_match=".*"):
    for key, count in errors.items():
        if not count:
            continue
        logger.info("%s", f"    {key}: {count}")

    def printhdr(x):
        if isinstance(vpp, IPTFSVPP):
            logger.info("%s", f"    IPTFS SA {x}:")
        else:
            logger.info("%s", f"    ETFS3 FLOW {x}:")

    recomp = re.compile(counter_match)

    nohdr = defaultdict(int)
    for index in sorted(counters):
        for key in sorted(counters[index]):
            count = counters[index][key]
            if not count:
                continue
            if not recomp.match(key):
                continue
            if not nohdr[index]:
                printhdr(index)
                nohdr[index] = True
            logger.info("%s", f"        {key}: {count}")

    nohdr = defaultdict(int)
    for index in sorted(pkts):
        for key in sorted(pkts[index]):
            count = pkts[index][key]
            ocount = octets[index][key]
            if not count and not ocount:
                continue
            if not recomp.match(key):
                continue
            if not nohdr[index]:
                printhdr(index)
                nohdr[index] = True
            logger.info("%s", f"        {key}: {count}: {ocount}")


def fail_test(args, reason, trex_stats, vstats, vpplist=None):
    """Fail the test passing the given reason. If stats are passed in then print the
    stats first.
    """
    logger.info("FAILURE DIAGS:")
    if trex_stats:
        pprint.pprint(trex_stats, indent=4)
    if vpplist is not None:
        for index, vpp in enumerate(vpplist):
            logger.info("%s", f"VPP HOST: {vpp.host}:")
            # We do not want bogus way late stats reported!
            # logger.info(vpp.vppctl("show errors"))
            dump_tun_stats(vpp, *vstats[index][-1][1:])
            dump_ifstats_one(vpp, vstats[index])
    if args.pause:
        logger.info("%s", f"Pausing after {reason}")
        result = input("Pausing with testbed UP, RETURN to continue, \"p\" for PDB: ")
        if result.strip().lower() == "p":
            pdb.set_trace()
    raise Exception(reason)


def check_missed(args, trex_stats, vstats, vpplist):
    p0missed = trex_stats[0]["rx-missed"]
    p0pct = trex_stats[0]["rx-missed-pct"]
    p1missed = trex_stats[1]["rx-missed"]
    p1pct = trex_stats[1]["rx-missed-pct"]
    #
    # Verify trex received all it sent.
    #
    if p0missed or p1missed:
        reason = f"FAILED: p0missed: {p0missed} ({p0pct}%) p1missed: {p1missed} ({p1pct}%)"
        fail_test(args, reason, trex_stats, vstats, vpplist)

    #
    # Verify trex received all VPP sent.
    #
    # This doesn't work for docker trex and ipsec right now b/c we still get arps apparently?
    #
    if args.is_docker and args.dont_use_tfs:
        return

    for i in range(0, 2):
        vpp = vpplist[i]
        trx = trex_stats[i]["ipackets"]
        vuser_tx = vstats[i][vpp.USER_IFINDEX]["/if/tx"]
        if trx != vuser_tx:
            reason = f"FAILED: vpp{i}/trex port{i} vuser_tx: {vuser_tx} != prx: {trx}"
            fail_test(args, reason, trex_stats, vstats, vpplist)


def log_packet_counts(vpplist, trex_stats, vstats):
    for i in range(0, 2):
        vpp = vpplist[i]
        oi = (i + 1) % 2
        missed = trex_stats[i]["rx-missed"]
        pct = trex_stats[i]["rx-missed-pct"]
        logging.info(
            "%s", "TEST INFO TREX: {}->{} tx: {} rx: {} missed: {} missed-pct {}".format(
                i, oi, trex_stats[i]["opackets"], trex_stats[oi]["ipackets"], missed, pct))
        tx = trex_stats[i]["opackets"]
        rx = vstats[i][vpp.USER_IFINDEX]["/if/rx"]
        missed = tx - rx
        if missed:
            pct = abs((missed / tx) * 100)
            mstr = "missed" if missed > 0 else "extra"
            missed = abs(missed)
            logging.info(
                "%s",
                f"TEST INFO VPP->TREX: {i} tx: {tx} rx: {rx} {mstr}: {missed} {mstr}-pct: {pct}")
        tx = trex_stats[i]["opackets"]
        rx = vstats[i][vpp.USER_IFINDEX]["/if/rx"]
        missed = tx - rx
        if missed:
            pct = abs((missed / tx) * 100)
            mstr = "missed" if missed > 0 else "extra"
            missed = abs(missed)
            logging.info(
                "%s",
                f"TEST INFO VPP->TREX: {i} tx: {tx} rx: {rx} {mstr}: {missed} {mstr}-pct: {pct}")


def finish_test(module_name, args, vpplist, trex, trex_stats, vstats):
    save_stats(module_name, "trex-stats", trex_stats)
    save_stats(module_name, "vpp-stats", vstats)

    if trex:
        if args.percentage is None or args.percentage <= 100:
            check_missed(args, trex_stats, vstats, vpplist)

        # logging.debug("TREX Stats:\n%s" % pprint.pformat(trex_stats, indent=4))

        log_packet_counts(vpplist, trex_stats, vstats)

    logging.info("TEST PASSED")

    if args.pause_on_success:
        input("Pausing after test, RETURN to continue")

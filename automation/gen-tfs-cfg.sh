#!/bin/bash
#
# January 11 2021, Christian Hopps <chopps@labn.net>
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
export VPPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
source $VPPDIR/automation/setup.sh
source $VPPDIR/automation/tfs-setup.sh

f_cc=0
f_no_pad=0
f_remove=0
f_null_crypto=0
f_use_chaining=0
f_use_etfs=0
f_use_ike=0
f_use_ipsec=1
f_use_iptfs=1
f_use_ipv6=0
f_use_ipv6_encap=0
f_use_macsec=0
f_use_policy=0
f_use_tunnel=1
f_use_udp=0
o_connections=1
o_iptfs_packet_size=1500
o_tfs_ether_rate=10G
o_tfs_max_latency=10000
o_tfs_mode=""

usage () {
    cat << EOF

$0: [-69acFIkKnNOpRPUx] [-l latency] [-M mode] [-m count] [-r rate] [-s size]

    count, rate, szie :: accepts "K" "Ki" and "k", KMGTPEZY are 1000 based otherwise 1024

    -6 :: IPv6 IPsec Tunnel
    -9 :: IPv6 User Traffic
    -a :: adaptive rate (congestion control mode)
    -c :: use encap chaining instead of copy [${f_use_chaining}]
    -F :: forwarding only (no iptfs no ipsec, no ipip)
    -I :: run with IKE instead of static iptfs config
    -K :: run with crypto-engine backend
    -k :: use MACSEC enKryption
    -l latency :: maximum latency (usecs) for user traffic [${o_tfs_max_latency}]
    -M mode :: TFS operating mode (encap-only, min-rate, fixed-rate)
    -m count :: number of connections for m-p2p
    -n :: use NULL encryption and authentication
    -N :: no iptfs (ipsec only)
    -O :: no ipsec (ipip only)
    -p :: use SA policy instead of interface config
    -P :: no pad (useful for tracing)
    -R :: remove the config
    -r rate :: the ethernet rate of the iptfs tunnel [${o_tfs_ether_rate}]
    -s size :: the L3 packet size of IPTFS packets [${o_iptfs_packet_size}]
    -U :: use IPsec UDP
    -V :: vpp native instead of DPDK (needed for interface names)
    -x :: etfs [${f_etfs}]
EOF
    exit 0
}

while getopts 69acFhIkKl:M:m:nNRr:OpPs:Vx opt; do
    case $opt in
        6)
            f_use_ipv6_encap=1
            ;;
        9)
            f_use_ipv6=1
            ;;
        a)
            f_cc=1
            ;;
        c)
            f_use_chaining=1
            ;;
        F)
            f_use_tunnel=0
            f_use_ipsec=0
            f_use_iptfs=0
            ;;
        I)
            f_use_ike=1
            ;;
        k)
            f_use_macsec=1
            ;;
        K)
            f_use_crypto_engine=1
            ;;
        l)
            o_tfs_max_latency="$OPTARG"
            ;;
        m)
            o_connections=${OPTARG}
            ;;
        M)
            o_tfs_mode="${OPTARG}"
            ;;
        N)
            f_use_iptfs=0
            ;;
        n)
            f_null_crypto=1
            ;;
        O)
            f_use_ipsec=0
            f_use_iptfs=0
            ;;
        p)
            f_use_policy=1
            ;;
        P)
            f_no_pad=1
            ;;
        r)
            o_tfs_ether_rate=${OPTARG}
            ;;
        R)
            f_remove=1
            ;;
        s)
            o_iptfs_packet_size=${OPTARG}
            ;;
        U)
            f_use_udp=1
            ;;
        V)
            f_vpp_native=1
            ;;
        x)
            f_use_iptfs=0
            f_use_etfs=1
            ;;
        -)
            break;
            ;;
        h)
            usage
            ;;
    esac
done
shift $(($OPTIND - 1))

declare -a vpp_ifnames
vpp_ifnames=()
for ((i=0; i<2; i++)); do
    if (( f_vpp_native )) &&  [[ -n "${testbed_interfaces[${HOSTNAME}-native-$i]}" ]]; then
        vpp_ifnames+=("${testbed_interfaces[${HOSTNAME}-native-$i]}")
    else
        vpp_ifnames+=("${testbed_interfaces[${HOSTNAME}-$i]}")
    fi
done

if (( f_use_etfs )); then
    # etfs specified in bits per millisecond
    o_tfs_ether_rate=$(($(get_value $o_tfs_ether_rate) / 1000))
else
    if [[ -e /etc/openwrt_release ]]; then
        # Awk on this system rounds down to 2^31
        o_tfs_ether_rate=$o_tfs_ether_rate
    else
        o_tfs_ether_rate=$(get_value $o_tfs_ether_rate)
    fi
fi
o_tfs_max_latency=$(get_value $o_tfs_max_latency)
o_iptfs_packet_size=$(get_value $o_iptfs_packet_size)
o_trace_count=$(get_value $o_trace_count)
o_connections=$(get_value $o_connections)

#vppconfig=/dev/stdout
vppconfig=/proc/self/fd/1
source $VPPDIR/automation/tfs-cfg-sub.sh

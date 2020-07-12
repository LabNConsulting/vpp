#!/bin/bash
#
# December 17 2020, Christian Hopps <chopps@labn.net>
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
export VPPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
source $VPPDIR/automation/setup.sh

#
# exports to config file pointed to in VPPCONFIG:
# IPID - decimal value of the host bits for the router.
# OTHER_IPID - IPID of the other router
# OTHER_PREIP - first 3 of dotted-quad for "remote" router network.
# PKTGEN_IP - directly connected IP of TREX for the router.
# THIS_PREIP - first 3 of dotted-quad for "local" router network.
# USEIF - interface used for p2p router connection
# USEIF_PREIP - first 3 of dotted-quad for USEIF interface.
#
#

if (($(id -u) == 0)); then
    SUDO=
else
    SUDO=sudo
fi

set -ex

f_cc=0
f_container_physical=0
f_exec=0
f_in_container=0
f_interactive=0
f_memif_master=0
f_no_pad=0
f_no_tfs_config=0
f_node_counters=0
f_null_crypto=0
f_remove=0
f_run_gdb=0
f_run_gdbserver=0
f_use_chaining=0
f_use_crypto_async=0
f_use_crypto_backends_mixed=0
f_use_crypto_engine=0
f_use_etfs=0
f_use_ike=0
f_use_ipsec=1
f_use_iptfs=1
f_use_ipv6=0
f_use_ipv6_encap=0
f_use_macsec=0
f_use_memif=0
f_use_policy=0
f_use_remote=0
f_use_tunnel=1
f_use_udp=0
f_vpp_native=0
o_buffer_size=0
o_buffers=30k
o_connections=1
o_event_log_size=0
o_gdb_symbol=""
o_integrity_ipaddrs=""
o_iptfs_packet_size=1500
o_main_core=0
o_rx_tfs_queues=0
o_rx_user_queues=0
o_rx_worker_starts=""
o_skip_cores=0
o_tfs_ether_rate=10G
o_tfs_max_latency=10000
o_tfs_mode=""
o_trace_count=0
o_trace_frame_queue=""
o_worker_range=""
o_workers=5

using_memif=0

usage () {
    cat << EOF
$0: [-69acCEFgiIkKnNOpPVxy] [-b count] [-B size] [-d desc ] [-D desc] [-e size]
    [-l latency] [-M mode] [-m count] [-q user-rx-queues] [-Q tfs-rx-queues] [-r rate]
    [-R rx-worker-start ] [-s size] [-S count] [-t count] [-T fq-index] [-w count]
    [-W worker-range] [-X symbol]

    desc - descriptor config e.g., "rx 2048" or "rx 2048 tx 4096"
    count, rate, szie :: accepts "K" "Ki" and "k", KMGTPEZY are 1000 based otherwise 1024
    worker-range - type=first:last[,type=first:last...] e.g. encap=2:3,decap=4:5
    rx-worker-starts - rx-first-user-thread,rx-first-tunnel-thread

    -6 :: IPv6 IPsec Tunnel
    -6 :: IPv6 User Traffic
    -a :: adaptive rate (congestion control mode)
    -A :: master role if using memif
    -b count :: minimum number of o_buffers to allocate to the pool [${o_buffers}]
    -B size :: size of o_buffers [${o_buffer_size}]
    -c :: use encap chaining instead of copy [${f_use_chaining}]
    -C :: in container [${f_in_container}]
    -d desc :: descriptor config for user interface [${desc_userif}]
    -D desc :: descriptor config for iptfs interface [${desc_tunif}]
    -e size :: event log size [${o_event_log_size}]
    -E :: exec vpp
    -F :: forwarding only (no iptfs no ipsec, no ipip)
    -g :: run with GDB
    -G :: run with GDB server
    -i :: run in interactive mode
    -I :: run with IKE instead of static iptfs config
    -J hostips :: host IP addresses for ssh integrity test
    -K :: run with crypto-engine backend
    -k :: use MACSEC enKryption
    -l latency :: maximum latency (usecs) for user traffic [${o_tfs_max_latency}]
    -M mode :: TFS operating mode (encap-only, min-rate, fixed-rate)
    -m count :: number of connections for m-p2p
    old: -m socket-path :: use memif in slave mode with socket-path [XXX broken]
    old: -M socket-path :: use memif in master mode with socket-path [XXX broken]
    -n :: use NULL encryption and authentication
    -N :: no iptfs (ipsec only)
    -O :: no ipsec (ipip only)
    -p :: use SA policy instead of interface config
    -P :: no pad (useful for tracing)
    -q :: number of rx user queues
    -Q :: number of rx tfs queues
    -r rate :: the ethernet rate of the iptfs tunnel [${o_tfs_ether_rate}]
    -R rx-worker-starts :: the starting workers for user and tfs ranges
    -s size :: the L3 packet size of IPTFS packets [${o_iptfs_packet_size}]
    -S count :: skip cores
    -t count :: number of packets to trace [${trace_count}]
    -T fq-index :: Enable tracing of frame-queue index
    -u :: do not configure iptfs (will be done later)
    -U :: use IPsec UDP
    -V :: vpp native instead of DPDK
    -w count :: number of workers [${o_workers}]
    -W worker-range :: static worker config
    -x :: etfs [${f_etfs}]
    -X symbol :: symbol to set a breakpoint on in gdb [${o_gdb_symbol}]
    -y :: Enable per node counters in stats segment [${f_node_counters}]
    -Y :: Enable physical interfaces in container [${f_container_physical}]
EOF
    exit 0
}

while getopts 69aAb:B:cCd:D:EFe:gGhH:iIJ:kKl:M:m:nNR:r:OpPq:Q:S:s:T:t:UuVW:w:xX:yYzZ opt; do
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
        A)
            f_memif_master=1
            ;;
        b)
            o_buffers=$OPTARG
            ;;
        B)
            o_buffer_size=$OPTARG
            ;;
        c)
            f_use_chaining=1
            ;;
        C)
            f_in_container=1
            ;;
        d)
            desc_userif="$OPTARG"
            ;;
        D)
            desc_tunif="$OPTARG"
            ;;
        e)
            o_event_log_size=${OPTARG}
            ;;
        E)
            f_exec=1
            ;;
        F)
            f_use_tunnel=0
            f_use_ipsec=0
            f_use_iptfs=0
            ;;
        g)
            f_interactive=1
            f_run_gdb=1
            ;;
        G)
            f_interactive=1
            f_run_gdbserver=1
            ;;
        H)
            HOSTNAME="${OPTARG}"
            ;;
        I)
            f_use_ike=1
            ;;
        J)
            o_integrity_ipaddrs="${OPTARG}"
            ;;
        k)
            f_use_macsec=1
            ;;
        K)
            f_use_crypto_engine=1
            ;;
        i)
            f_interactive=1
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
        # m)
        #     f_use_memif=1
        #     f_memif_master=1
        #     o_memif_socket="${OPTARG}"
        #     echo "Warning: memif is broken currently for dpdk use"
        #     ;;
        # M)
        #     f_use_memif=1
        #     f_memif_master=0
        #     o_memif_socket="${OPTARG}"
        #     echo "Warning: memif is broken currently for dpdk use"
        #     ;;
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
        q)
            o_rx_user_queues=${OPTARG}
            ;;
        Q)
            o_rx_tfs_queues=${OPTARG}
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
            o_rx_worker_starts=${OPTARG}
            ;;
        S)
            o_skip_cores=${OPTARG}
            ;;
        s)
            o_iptfs_packet_size=${OPTARG}
            ;;
        t)
            o_trace_count=${OPTARG}
            ;;
        T)
            o_trace_frame_queue=${OPTARG}
            ;;
        U)
            f_use_udp=1
            ;;
        u)
            f_no_tfs_config=1
            ;;
        V)
            f_vpp_native=1
            ;;
        w)
            o_workers=${OPTARG}
            ;;
        W)
            o_worker_range=${OPTARG}
            ;;
        x)
            f_use_iptfs=0
            f_use_etfs=1
            ;;
        X)
            o_gdb_symbol=${OPTARG}
            ;;
        y)
            f_node_counters=1
            ;;
        Y)
            f_container_physical=1
            ;;
        z)
            f_use_crypto_async=1
            ;;
        Z)
            f_use_crypto_backends_mixed=1
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

o_buffers=$(get_value $o_buffers)
o_event_log_size=$(get_value $o_event_log_size)
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

echo MACSEC FLAG: ${f_use_macsec}
echo MIXED_CRYPTO: ${f_use_crypto_backends_mixed}

if (( o_buffer_size )); then
    o_buffer_size=$(get_value $o_buffer_size)
    BUFSIZE_ARG="default data-size $o_buffer_size"
else
    if (( f_use_iptfs || f_use_etfs )); then
        o_buffer_size=$(get_value 10k)
        BUFSIZE_ARG="default data-size $o_buffer_size"
    else
        BUFSIZE_ARG=""
    fi
fi

#
# Set a bunch of environment variables based on where we are running.
#
source $VPPDIR/automation/tfs-setup.sh

if [[ -e /etc/init.d/tfs ]]; then
    /etc/init.d/tfs stop
fi

if LD_LIBRARY_PATH=$VPPLDPATH $VPPPATH/vppctl show version > /dev/null 2> /dev/null; then
    echo "VPP already running!"
    exit 1
fi

declare -a vpp_ifnames
vpp_ifnames=()
for ((i=0; i<2; i++)); do
    if (( f_vpp_native )) &&  [[ -n "${testbed_interfaces[${HOSTNAME}-native-$i]}" ]]; then
        vpp_ifnames+=("${testbed_interfaces[${HOSTNAME}-native-$i]}")
    else
        vpp_ifnames+=("${testbed_interfaces[${HOSTNAME}-$i]}")
    fi
done


#
# This block sets up the local veth path to vpp for ssh testing
#
if [[ -n "${o_integrity_ipaddrs}" ]]; then
    # NB exceeding 15-char interface name length yields
    # "Attribute failed policy validation"
    # debug "setting up for integrity test, USER=${USER}"
    if ! ip link show veh-${USER} > /dev/null 2>&1; then
        # debug "doing link add"
        sudo ip link add veh-${USER} type veth peer name vev-${USER}
        # debug "link add returned $?"
    fi
    sudo ip link set dev veh-${USER} up
    sudo ip link set dev vev-${USER} up
    # debug "link up done"

    # the following enables tcp checksums
    sudo ethtool -K veh-${USER} tx off
    sudo ethtool -K vev-${USER} tx off
    # debug "ethtool tx off done"

    sudo ip link set veh-${USER} mtu 9000
    sudo ip link set vev-${USER} mtu 9000
    # debug "link set mtu done"

    IPA_LOCAL=${o_integrity_ipaddrs%%:*}
    PORTNUM_LOCAL=${o_integrity_ipaddrs##*:}

    # debug "setting ip addr to ${IPA_LOCAL}"
    sudo ip address flush dev veh-${USER}
    sudo ip address add ${IPA_LOCAL}/24 dev veh-${USER}
    # debug "ip addr done"

    # override default name
    vpp_ifnames[0]=host-vev-${USER}

fi

max_cpu=$(grep ^processor /proc/cpuinfo|wc -l)
if (( f_in_container )); then
    if (( (2 * o_workers) > (max_cpu - 1) )); then
        if (( max_cpu % 2 )); then
            o_workers=$((max_cpu / 2))
        else
            o_workers=$(((max_cpu - 1) / 2))
        fi
        echo "Warning: reduce workers to $o_workers since docker containers shares the same CPUs"
        exit 1
    fi
else
    if (( o_workers > (max_cpu - 1) )); then
        o_workers=$((max_cpu - 1))
        echo "Warning: reduce workers to $o_workers (not enough cores)"
        exit 1
    fi
fi

if (( !o_rx_user_queues )); then
    if (( (o_workers -1) >= 8 )); then
        o_rx_user_queues=2
    fi
fi
if (( !o_rx_user_queues )); then
    o_rx_user_queues=1
fi
if (( !o_rx_tfs_queues )); then
    o_rx_tfs_queues=1
fi

declare DPDK_BASE_CONFIG=""
declare DPDK_DEV_CONFIG=""
declare DPDK_VDEV_CONFIG=""
declare DPDK_CRYPTO_CONFIG=""

declare _memif1
declare _memif1id
declare _memif1sockid

if (( f_vpp_native )); then
    if [[ "${testbed_interfaces[${this_host}-native-0]}" ]]; then
        declare dev0name=${testbed_interfaces[${this_host}-native-0]}
    else
        declare dev0name=${testbed_interfaces[${this_host}-0]}
    fi
    if [[ "${testbed_interfaces[${this_host}-native-1]}" ]]; then
        declare dev1name=${testbed_interfaces[${this_host}-native-1]}
    else
        declare dev1name=${testbed_interfaces[${this_host}-1]}
    fi

    if [[ $dev0name =~ avf-0 ]]; then
        declare _dev0=${dev0name/avf-0\//}
    else
        declare _dev0=${dev0name/*Ethernet/}
    fi

    if [[ $dev1name =~ avf-0 ]]; then
        declare _dev1=${dev1name/avf-0\//}
    elif [[ $dev1name =~ memif ]]; then
        declare _memif1=${dev1name/memif/}
        declare _memifid1=${_memif1#*/}
        declare _memifsockid1=${_memif1%/*}
        if (( f_memif_master )); then
            declare memif_ms="master"
        else
            declare memif_ms="slave"
        fi
    else
        declare _dev1=${dev1name/*Ethernet/}
    fi

    if [[ "$(uname -m)" != "aarch64" ]]; then
        _pcidevbus0=${_dev0%%/*}
        _pcidevslot0=${_dev0%/*}; _pcidevslot0=${_pcidevslot0#*/}
        _pcidevfn0=${_dev0##*/}
        _pcidev0=$(printf "0000:%02x:%02x.%x" 0x$_pcidevbus0 0x$_pcidevslot0 0x$_pcidevfn0)
        declare _pciifname0=$(ls /sys/bus/pci/devices/${_pcidev0}/net/)

        if [[ $dev1name =~ memif ]]; then
            using_memif=1
        else
            _pcidevbus1=${_dev1%%/*}
            _pcidevslot1=${_dev1%/*}; _pcidevslot1=${_pcidevslot1#*/}
            _pcidevfn1=${_dev1##*/}
            _pcidev1=$(printf "0000:%02x:%02x.%x" 0x$_pcidevbus1 0x$_pcidevslot1 0x$_pcidevfn1)
            declare _pciifname1=$(ls /sys/bus/pci/devices/${_pcidev1}/net/)
        fi
    fi

    # This isn't used right now
    if [[ $dev1name =~ Hundred ]]; then
        native_desc_userif="rx $((2 * 1024)) tx 4096"
        native_desc_tunif="rx $((2 * 1024)) tx 4096"
    else
        native_desc_userif="rx $((2 * 1024)) tx 2048"
        native_desc_tunif="rx $((2 * 1024)) tx 2048"
    fi
elif (( f_in_container )) && (( !f_container_physical )); then
    declare NIC0=eth0
    declare NIC1=eth1
    if ip link show p2p0 > /dev/null 2>&1; then
        NIC0=p2p0
        NIC1=p2p1
    elif ip link show eth2 > /dev/null 2>&1; then
        NIC0=eth1
        NIC1=eth2
    fi

    # If this is a generic network we will have IP address and we need to delete it.
    # Also set our MAC address
    declare ethx_addr=$(ip -4 addr show $NIC0 | awk '/inet /{print $2}')
    [[ -z "$ethx_addr" ]] || ip addr del $ethx_addr dev $NIC0
    ip link set dev $NIC0 address ${testbed_macaddr[${this_host}-0]}

    # DPDK_CONFIG="dpdk { dev default { num-rx-queues 1 num-tx-queues 2 } "
    DPDK_BASE_CONFIG+="proc-type primary log-level pmd,debug "

    DPDK_VDEV_CONFIG+="vdev eth_af_packet0,iface=$NIC0 "
    if (( f_use_memif )); then
        DPDK_VDEV_CONFIG+="vdev net_memif"
        if (( f_memif_master )); then
            DPDK_VDEV_CONFIG+=",socket=${o_memif_socket},rsize=12,role=master,id=0"
        else
            DPDK_VDEV_CONFIG+=",socket=${o_memif_socket},rsize=12,role=slave,id=0"
        fi
        DPDK_VDEV_CONFIG+=",mac=${testbed_macaddr[${this_host}-1]} "
    else
        # If this is a generic network we will have IP address and we need to delete it.
        # Also set our MAC address
        ethx_addr=$(ip -4 addr show $NIC1 | awk '/inet /{print $2}')
        [[ -z "$ethx_addr" ]] || ip addr del $ethx_addr dev $NIC1
        ip addr add 14.14.14.${IPID}/24 dev $NIC1
        ip link set dev $NIC1 address ${testbed_macaddr[${this_host}-1]}

        DPDK_VDEV_CONFIG+="vdev eth_af_packet1,iface=$NIC1 "
    fi
    #desc_userif="rx 512 tx 1024"
    #desc_tunif="rx 512 tx 1024"
elif [[ $(uname -m) == "aarch64" ]]; then
    DPDK_DEV_DEFAULTS+=" vlan-strip-offload off "
    DPDK_VDEV_CONFIG+="vdev net_mvpp2,iface=eth0,iface=eth1 "
    desc_userif="rx 1024 tx 1024"
    desc_tunif="rx 1024 tx 1024"
    MARVELL_PLUGIN="plugin marvell_plugin.so { disable }"
elif [[ $(uname -m) == "x86_64" ]]; then
    # Convert interface names to PCI addresses
    declare dev0name=${testbed_interfaces[$HOSTNAME-0]}
    declare dev1name=${testbed_interfaces[$HOSTNAME-1]}
    if [[ $dev0name =~ avf-0 ]]; then
        declare _dev0=${testbed_interfaces[$HOSTNAME-0]/avf-0\//}
    else
        declare _dev0=${testbed_interfaces[$HOSTNAME-0]/*Ethernet/}
    fi
    if [[ $dev1name =~ avf-0 ]]; then
        declare _dev1=${testbed_interfaces[$HOSTNAME-1]/avf-0\//}
    else
        declare _dev1=${testbed_interfaces[$HOSTNAME-1]/*Ethernet/}
    fi
    _pcidevbus0=${_dev0%%/*}
    _pcidevbus1=${_dev1%%/*}
    _pcidevslot0=${_dev0%/*}; _pcidevslot0=${_pcidevslot0#*/}
    _pcidevslot1=${_dev1%/*}; _pcidevslot1=${_pcidevslot1#*/}
    _pcidevfn0=${_dev0##*/}
    _pcidevfn1=${_dev1##*/}
    _pcidev0=$(printf "0000:%02x:%02x.%x" 0x$_pcidevbus0 0x$_pcidevslot0 0x$_pcidevfn0)
    _pcidev1=$(printf "0000:%02x:%02x.%x" 0x$_pcidevbus1 0x$_pcidevslot1 0x$_pcidevfn1)

    declare using_rdma=0
    if [[ $dev0name =~ avf-0 ]]; then
        :
    else
        if [[ $dev0name =~ Hundred ]]; then
            dpdk_desc_userif="rx $((4 * 1024)) tx 4096"
            dpdk_desc_tunif="rx $((4 * 1024)) tx 4096"
            using_rdma=1
        else
            dpdk_desc_userif="rx $((2 * 1024)) tx $((2 * 1024))"
            dpdk_desc_tunif="rx $((2 * 1024)) tx $((2 * 1024))"
        fi
        DPDK_DEV_CONFIG+="dev $_pcidev0 { num-rx-queues $o_rx_user_queues } "
    fi
    if [[ $dev1name =~ avf-0 ]]; then
        :
    else
        if [[ $dev1name =~ Hundred ]]; then
            using_rdma=1
        fi
        DPDK_DEV_CONFIG+="dev $_pcidev1 { num-rx-queues $o_rx_tfs_queues } "
    fi

    if (( ! using_rdma )); then
        RDMA_PLUGIN="plugin rdma_plugin.so { disable }"
    fi
fi

if (( ! f_use_crypto_engine )); then
    if (( f_null_crypto )); then
        declare vdevbase=crypto_null
    elif [[ $(uname -m) == "aarch64" ]]; then
        declare vdevbase=crypto_mvsam
    else
        declare vdevbase=crypto_aesni_gcm
    fi
    # if [[ $(uname -m) == "aarch64" ]]; then
    #     DPDK_VDEV_CONFIG+="vdev ${vdevbase}0 "
    # else
        for numadir in /sys/devices/system/node/node[0-9]*; do
            numa=$(basename $numadir)
            numa=${numa#node}
            # Now need twice the queues b/c of crypto engine :(
            cpucount=$(($(ls -d ${numadir}/cpu[0-9]* | wc -l) * 2))
            DPDK_VDEV_CONFIG+="vdev ${vdevbase}${numa},max_nb_queue_pairs=${cpucount},socket_id=${numa} "
        done
    # fi
fi

declare DPDK_CONFIG=""
if [[ -n "$DPDK_BASE_CONFIG" || -n "$DPDK_DEV_CONFIG" || -n "$DPDK_VDEV_CONFIG" || -n "$DPDK_CRYPTO_CONFIG" ]]; then
    if [[ -z "$DPDK_DEV_CONFIG" ]]; then
        DPDK_BASE_CONFIG+="no-pci "
    fi
    if (( ! f_use_chaining )); then
        DPDK_BASE_CONFIG+=" no-multi-seg "
    fi
    DPDK_BASE_CONFIG+=" no-tx-checksum-offload "
    if [[ -n "$DPDK_DEV_DEFAULTS" ]]; then
        DPDK_DEV_DEFAULTS="dev default { $DPDK_DEV_DEFAULTS }"
    fi
    DPDK_CONFIG="dpdk { $DPDK_BASE_CONFIG $DPDK_DEV_DEFAULTS $DPDK_DEV_CONFIG $DPDK_VDEV_CONFIG $DPDK_CRYPTO_CONFIG }"
    using_dpdk=1
else
    # No DPDK config, disable the plugin
    DPDK_PLUGIN="plugin dpdk_plugin.so { disable }"
    using_dpdk=0
fi

vppconfig=/tmp/vpp-startup-${USER}.conf
swandir=/usr/local/etc/strongswan.d
SWANCTLDIR=/usr/local/etc/swanctl

echo -n > $vppconfig

# This doesn't work if we restart the log (which we normally do)
# echo "elog trace api barrier dispatch" >> $vppconfig

if (( $o_event_log_size )); then
    echo "Event Logging"
    echo "event-logger resize ${o_event_log_size}" >> $vppconfig
    echo "event-logger resize ${o_event_log_size}" >> $vppconfig
fi

if [[ -n "${o_integrity_ipaddrs}" ]]; then
    cat >> $vppconfig << EOF
create host-interface name vev-${USER}
set interface state host-vev-${USER} up

EOF
fi

if [[ $o_trace_frame_queue ]]; then
    echo "Tracing Frame Queue ${o_trace_frame_queue}"
    echo "trace frame-queue on index ${o_trace_frame_queue}" >> $vppconfig
fi

declare iptfs_ranges_config=""
if [[ "$o_worker_range" ]]; then
    for elt in $(echo $o_worker_range | tr ',' ' '); do
        declare keyval=($(echo $elt | tr '=' ' '))
        declare firstlast=($(echo ${keyval[1]} | tr ':' ' '))
        iptfs_ranges_config+=" ${keyval[0]} ${firstlast[@]}"
    done
fi
if [[ "$iptfs_ranges_config" ]]; then
   echo "iptfs worker ranges$iptfs_ranges_config" >> $vppconfig
fi

# echo "set logging class avf level debug" >> $vppconfig

if (( f_vpp_native )); then
    for ((i=0; i<2; i++)); do
        declare _nnname=${testbed_interfaces[${this_host}-$i]}
        if [[ "${testbed_interfaces[${this_host}-native-$i]}" ]]; then
            declare _name=${testbed_interfaces[${this_host}-native-$i]}
            if [[ -z "$_nnname" ]]; then
                _nnname=$_name
            fi
        else
            declare _name=$_nnname
        fi
        declare _ipcidev=_pcidev$i
        declare _nqueues=$o_rx_user_queues
        if (( i )); then
            _nqueues=$o_rx_tfs_queues
        fi
        if [[ $_name =~ avf-0 ]]; then
            if (( ! f_in_container )); then
                setup_avf ${this_host} ${!_ipcidev} ${testbed_macaddr[${this_host}-native-$i]}
            fi
            # echo "create interface avf ${!_ipcidev} name $_nnname rx-queue-size $((1024 * 2)) tx-queue-size $((1024*2)) num-rx-queues $_nqueues" >> $vppconfig
            echo "create interface avf ${!_ipcidev} rx-queue-size $((1024 * 2)) tx-queue-size $((1024*2)) num-rx-queues $_nqueues" >> $vppconfig
        elif [[ $_name =~ mv-ppio ]]; then
            declare _ethdev=${_name#mv-ppio-}
            _ethdev=${_ethdev%/*}
            echo "create interface marvell pp2 name eth${_ethdev} rx-queue-size $((1024 * 2)) tx-queue-size $((1024*2))" >> $vppconfig
            # We need the name name
            testbed_interfaces[${this_host}-$i]="$_name"
        elif [[ $_name =~ memif ]]; then
            declare _memifid=_memifid$i
            declare _memifsockid=_memifsockid$i
            declare memif_filename="/run/vpp/shared/memif${!_memifsockid}"
            echo "create memif socket id ${!_memifsockid} filename ${memif_filename}" >> $vppconfig
            echo "create interface memif id ${!_memifid} socket-id ${!_memifsockid} hw-addr ${testbed_macaddr[${this_host}-$i]} ${memif_ms}" >> $vppconfig
        elif [[ $_name =~ Hundred ]]; then
            cat >> $vppconfig << EOF
create int rdma host-if ${_pciifname0} name ${vpp_ifnames[$i]} num-rx-queues ${o_rx_user_queues}
EOF
        fi
    done
else
    for ((i=0; i<2; i++)); do
        declare _name=${testbed_interfaces[${this_host}-$i]}
        declare _ipcidev=_pcidev$i
        if [[ $_name =~ VirtualFunctionEthernet ]]; then
            if (( ! f_in_container )); then
                setup_avf ${this_host} ${!_ipcidev} ${testbed_macaddr[${this_host}-$i]}
            fi
        fi
    done
fi
# set interface mac address ${vpp_ifnames[$i]} ${testbed_macaddr[${this_host}-native-$i]}

# Duplicated block: wipes out eariler values and breaks integrity test.
# Probably # should be deleted.
#declare -a vpp_ifnames
#vpp_ifnames=()
#for ((i=0; i<2; i++)); do
#    if (( f_vpp_native )) &&  [[ -n "${testbed_interfaces[${HOSTNAME}-native-$i]}" ]]; then
#        vpp_ifnames+=("${testbed_interfaces[${HOSTNAME}-native-$i]}")
#    else
#        vpp_ifnames+=("${testbed_interfaces[${HOSTNAME}-$i]}")
#    fi
#done

desc_userif=${desc_userif:-$dpdk_desc_userif}
if [[ $desc_userif ]]; then
    if ! [[ $dev0name =~ avf-0 ]]; then
        echo "set dpdk interface descriptors ${vpp_ifnames[0]} ${desc_userif}" >> $vppconfig
    fi
fi

desc_tunif=${desc_userif:-$dpdk_desc_tunif}
if [[ $desc_tunif ]]; then
    if ! [[ $dev1name =~ avf-0 ]]; then
        echo "set dpdk interface descriptors ${vpp_ifnames[1]} ${desc_tunif}" >> $vppconfig
    fi
fi

VPPVER=$(ls ${VPPBLDROOT}/lib/libvatplugin.so.*)
VPPVER=${VPPVER#*libvatplugin.so.}
VPPMAJVER=VPPVER=${VPPVER%%.*}
if (( VPPMAJVER >= 20 )); then
    arpcmd="neighbor"
else
    arpcmd="arp"
fi

# Doesn't work on mlnx
# set interface mac address ${vpp_ifnames[0]} ${testbed_macaddr[${this_host}-0]}
# set interface mac address ${vpp_ifnames[1]} ${testbed_macaddr[${this_host}-1]}

if (( f_use_crypto_backends_mixed )); then
    # overload f_memif_master to distinguish between the two VPP instancs
    if (( f_memif_master )); then
	# dpdk crypto
	echo "ipsec select backend esp 1" >> $vppconfig
    else
	# vpp native crypto
	echo "ipsec select backend esp 0" >> $vppconfig
    fi
else
    if (( ! f_use_crypto_engine )); then
	echo "ipsec select backend esp 1" >> $vppconfig
    else
	echo "ipsec select backend esp 0" >> $vppconfig
	# echo "set crypto handler aes-256-gcm ipsecmb" >> $vppconfig
    fi
fi

if (( f_use_crypto_async )); then
    echo "set ipsec async mode on" >> $vppconfig
fi

declare rx_user_start=0
declare rx_tfs_start=${o_rx_user_queues}
# For 3 core macchiatobin setup we probably want rx and tx on same core, decap alone
# declare rx_tfs_start=2
if [[ "$o_rx_worker_starts" ]]; then
    declare vals=(${o_rx_worker_starts/,/ })
    rx_user_start=${vals[0]}
    rx_tfs_start=${vals[1]}
elif [[ ! "$o_worker_range" ]] && (( $o_workers > 4 )); then
    # The user has not specified the start locations, and has not specified
    # worker ranges, so they will be determined algorithmically, so we want to
    # start the TFS after the encap range.
    chunk=$(($o_workers / 5))
    leftovers=$(($o_workers % 5))
    if (( $leftovers > 2 )); then
        rx_tfs_start=$((chunk + 1))
    else
        rx_tfs_start=$chunk
    fi
fi
if (( o_rx_user_queues > 1 )); then
    q_worker=0
    for ((i=0; i<$o_rx_user_queues; i++)); do
        echo "set interface rx-placement ${vpp_ifnames[0]} queue $i worker $(($i + $rx_user_start))" >> $vppconfig
    done
else
    echo "set interface rx-placement ${vpp_ifnames[0]} worker $rx_user_start" >> $vppconfig
fi
if (( o_rx_tfs_queues > 1 )); then
    q_worker=0
    for ((i=0; i<$o_rx_tfs_queues; i++)); do
        echo "set interface rx-placement ${vpp_ifnames[1]} queue $i worker $(($i + $rx_tfs_start))" >> $vppconfig
    done
else
    echo "set interface rx-placement ${vpp_ifnames[1]} worker $rx_tfs_start" >> $vppconfig
fi

echo "set int state ${vpp_ifnames[0]} up" >> $vppconfig
echo "set int state ${vpp_ifnames[1]} up"  >> $vppconfig
if (( ! f_use_etfs )); then
    echo "set int ip address ${vpp_ifnames[0]} $(make_v4v6_user_prefix ${user_intf_addr})" >> $vppconfig
    for ((i=0; i < o_connections; i++)); do
        echo "set int ip address ${vpp_ifnames[1]} $(make_v4v6_tfs_prefix $(get_tfs_intf_addr $i $o_connections))" >> $vppconfig
    done
    if (( f_use_ipv6 )); then
        echo "set int ip address ${vpp_ifnames[0]} $(make_v4v6_user_prefix ${user_intf_addr})" >> $vppconfig
    fi
fi

echo >> $vppconfig

if (( f_use_etfs )); then
    if (( o_connections > 1 )); then
	for ((i=0; i < o_connections; i++)); do
	    vlan=$(( 100 + i ))
	    cat >> $vppconfig <<- EOF
		create sub-interfaces ${vpp_ifnames[0]} ${vlan}
		set int state ${vpp_ifnames[0]}.${vlan} up
		create sub-interfaces ${vpp_ifnames[1]} ${vlan}
		set int state ${vpp_ifnames[1]}.${vlan} up
EOF
	done
    fi
else
    for ((i=0; i < o_connections; i++)); do
        declare remote_tfs_ip=$(make_v4v6_tfs_addr $(get_tfs_remote_ip $i $o_connections))
        if (( ! f_vpp_native )); then
            echo "set ip ${arpcmd} ${vpp_ifnames[1]} ${remote_tfs_ip} ${other_mac} static" >> $vppconfig
        else
            declare other_mac_native=${testbed_macaddr[${other_host}-native-1]}
            if [[ -z "$other_mac_native" ]]; then
                declare other_mac_native=${testbed_macaddr[${other_host}-1]}
            fi
            echo "set ip ${arpcmd} ${vpp_ifnames[1]} ${remote_tfs_ip} ${other_mac_native} static" >> $vppconfig
        fi
    done

    echo "set ip ${arpcmd} ${vpp_ifnames[0]} $(make_v4v6_user_addr ${PKTGEN_IP}) ${trex_mac} static" >> $vppconfig
fi

if (( f_use_ipv6 )); then
    echo "ip6 nd ${vpp_ifnames[0]} ra-suppress" >> $vppconfig
    # echo "ip6 nd ${vpp_ifnames[0]} ra-suppress-link-layer" >> $vppconfig
fi

if (( f_use_ipv6_encap )); then
    echo "ip6 nd ${vpp_ifnames[1]} ra-suppress" >> $vppconfig
    # echo "ip6 nd ${vpp_ifnames[1]} ra-suppress-link-layer" >> $vppconfig
fi

if (( o_trace_count )); then
    cat >> $vppconfig << EOF
trace add af-packet-input ${o_trace_count}
trace add avf-input ${o_trace_count}
EOF
    if ((using_dpdk)); then
        cat >> $vppconfig << EOF
trace add dpdk-input ${o_trace_count}
trace add dpdk-crypto-input ${o_trace_count}
EOF
    fi
    if (( using_rdma )); then
        cat >> $vppconfig << EOF
trace add rdma-input ${o_trace_count}
EOF
    fi
    if (( f_use_etfs )); then
        cat >> $vppconfig << EOF
trace add etfs-output ${o_trace_count}
trace add etfs-decap-rx ${o_trace_count}
trace add etfs-decap-processor ${o_trace_count}
EOF
    fi
    if (( f_use_iptfs )); then
        cat >> $vppconfig << EOF
trace add iptfs-decap ${o_trace_count}
trace add iptfs-pacer ${o_trace_count}
trace add iptfs-output ${o_trace_count}
trace add iptfs-encap-enq ${o_trace_count}
trace add iptfs-encap4-tun ${o_trace_count}
trace add iptfs-encap6-tun ${o_trace_count}
EOF
    fi
fi

# Generate the TFS config
if (( ! f_no_tfs_config )); then
    source $VPPDIR/automation/tfs-cfg-sub.sh
fi

# Either iptfs-encap or iptfs-output will trace these
# trace add iptfs-zpool-poller ${o_trace_count}

# Create a loopback interface as last command useful for checking that all
# config applied if nothing else.
cat >> $vppconfig << EOF
create loopback interface
set int state loop0 up
EOF

if (( !using_memif )); then
    declare startup_config="startup-config $vppconfig"
else
    declare startup_config=""
fi

if (( f_use_remote )); then
    clisock="cli-listen /var/run/vpp-cli.sock"
    apisock="socket-name /var/run/vpp-api.sock"
    statsock="socket-name /var/run/vpp-stat.sock"
else
    clisock="cli-listen /run/vpp/cli.sock"
    apisock="default"
    statsock="default"
fi
if (( f_node_counters )); then
    statsock+=" per-node-counters on"
fi

# Pick different cores for the containers
worker_config=""
if (( o_skip_cores )); then
    worker_config+=" skip-cores ${o_skip_cores}"
    # For some reason we can't have a shared-main-core config with skip cores maybe
    # container stuff
    #o_main_core_config="main-core $(( o_skip_cores ))"
else
    o_main_core_config="main-core $o_main_core"
fi
worker_config+=" workers $o_workers"

if (( f_interactive )); then
    interactive_arg="interactive"
else
    interactive_arg="nodaemon"
fi
SCONFIG="unix { $interactive_arg cli-no-banner log /tmp/vpp.log coredump-size unlimited full-coredump gid vpp ${clisock} ${startup_config} } cpu { $o_main_core_config $worker_config } api-trace { on } socksvr { ${apisock} } statseg { ${statsock} } buffers { $BUFSIZE_ARG buffers-per-numa $o_buffers } plugins { path $VPPPLUGINS $DPDK_PLUGIN $MARVELL_PLUGIN $RDMA_PLUGIN } $DPDK_CONFIG punt { socket /tmp/punt-server.sock }"

if (( using_memif )); then
    if (( !f_memif_master )); then
        for ((i=0; i<120; i++)); do
            echo "Waiting for memif master to come up"
            sleep 1
            if [[ -e ${memif_filename} ]]; then
                break
            fi
        done
    fi
fi

if [[ -z "$VPPLDPATH" ]]; then
    PRELOAD="LD_PRELOAD=/usr/lib/libmusdk.so"
fi

if (( f_exec )); then
    echo "Execing vpp with config: ${startup_config}: args: ${SCONFIG}"
    export LD_LIBRARY_PATH=$VPPLDPATH
    if (( f_run_gdbserver )); then
        exec gdbserver :50${IPID} $VPPPATH/vpp $SCONFIG
    else
        exec $VPPPATH/vpp $SCONFIG
    fi
elif (( f_run_gdbserver )); then
    echo "Starting vpp in GDB with config: ${startup_config}: args: ${SCONFIG}"
    $SUDO gdbserver --wrapper env LD_LIBRARY_PATH=$VPPLDPATH ${PRELOAD} -- :5000 $VPPPATH/vpp $SCONFIG
elif (( f_run_gdb )); then
    echo "Starting vpp in GDB with config: ${startup_config} args: ${SCONFIG}"
    if [[ -n "${o_gdb_symbol}" ]]; then
        $SUDO env LD_LIBRARY_PATH=$VPPLDPATH ${PRELOAD} gdb $VPPPATH/vpp -ex "b ${o_gdb_symbol}" -ex "run $SCONFIG"
    else
        $SUDO env LD_LIBRARY_PATH=$VPPLDPATH ${PRELOAD} gdb $VPPPATH/vpp $BREAKARG -ex "run $SCONFIG"
    fi
else
    echo "Starting vpp with config: ${startup_config} LD_LIBRARY_PATH=$VPPLDPATH"
    $SUDO env LD_LIBRARY_PATH=$VPPLDPATH ${PRELOAD} $VPPPATH/vpp $SCONFIG
fi

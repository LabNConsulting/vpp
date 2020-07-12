#!/bin/bash
#
# June 28 2020, Christian E. Hopps <chopps@gmail.com>
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
source $VPPDIR/automation/tfs-setup.sh

set -e

SUDO=sudo
if [[ ! -e ./t-rex-64 ]]; then
    if [[ ! -e /opt/trex/current ]]; then
        echo "No /opt/trex/current found"
        exit 1
    fi
    cd /opt/trex/current
fi

usage () {
    cat << EOF
$0: [-9CePV] [-c cores] [-v verbosity]

    -9 :: Use IPv6
    -C :: In container (docker)
    -e :: run for etfs3
    -P :: No PCI
    -V :: Use Native MAC address for peers
EOF
    exit 1
}

f_etfs3=0
f_container=0
f_container_physical=0
f_nopci=0
f_use_ipv6=0
f_use_native_mac=0
o_cores=1
v_flag=""

while getopts 9Cc:ePCVv:Y opt; do
    case $opt in
        9)
            f_use_ipv6=1
            ;;
        c)
            o_cores=${OPTARG}
            ;;
        C)
            f_container=1
            SUDO=
            ;;
        e)
            f_etfs3=1
            ;;
        P)
            f_nopci=1
            ;;
        v)
            v_flag="-v ${OPTARG}"
            ;;
        V)
            f_use_native_mac=1
            ;;
        Y)
            SUDO=sudo
            f_container_physical=1
            ;;
    esac
done
shift $(($OPTIND - 1))

if (( f_container )) && (( !f_container_physical )); then
    NIC0=eth0
    NIC1=eth1
    if ip link show eth2 > /dev/null 2>&1; then
        NIC0=eth1
        NIC1=eth2
    fi

    if ip link show p2p0 > /dev/null 2>&1; then
        NIC0=p2p0
        NIC1=p2p1
    fi
else
    NIC0=${testbed_interfaces[${this_host}-0]}
    NIC1=${testbed_interfaces[${this_host}-1]}
fi

#
# Setup the environment
#

if (( f_container )) && (( !f_container_physical )); then
    if (( f_nopci )); then
        ip route del default || true
        export TREX_PORTID0=$NIC0
        export TREX_PORTID1=$NIC1
    else
        export TREX_PORTID0=$(readlink /sys/class/net/$NIC0/device)
        export TREX_PORTID1=$(readlink /sys/class/net/$NIC1/device)
        TREX_PORTID0=${TREX_PORTID0#../../../}
        TREX_PORTID0=${TREX_PORTID0#*:}
        TREX_PORTID1=${TREX_PORTID1#../../../}
        TREX_PORTID1=${TREX_PORTID1#*:}
    fi

    nic0_intf_addr=$(ip -4 addr show $NIC0 | awk '/inet /{print $2}')
    nic0_intf_ip=${nic0_intf_addr%/*}

    nic1_intf_addr=$(ip -4 addr show $NIC1 | awk '/inet /{print $2}')
    nic1_intf_ip=${nic1_intf_addr%/*}

    prep_ip () {
        local intf=$1
        local macaddr=$2
        local ifid=${intf#eth}
        local intf_addr=$(ip -4 addr show $intf | awk '/inet /{print $2}')
        ip addr del $intf_addr dev $intf
        ip link set $intf address ${macaddr}
    }

    prep_ip $NIC0 ${testbed_macaddr[${this_host}-0]}
    prep_ip $NIC1 ${testbed_macaddr[${this_host}-1]}
else
    TREX_PORTID0=$NIC0
    TREX_PORTID1=$NIC1
    nic0_intf_ip="11.11.11.253"
    nic1_intf_ip="12.12.12.253"
fi


# XXX need to make this generic using array of servers
declare -a servers=(${testbed_servers[$TESTBED]})
echo "Servers: ${testbed_servers[$TESTBED]}"
echo "Servers as array: ${servers[*]}"

CFG=/tmp/trex_cfg_${USER}.yaml

if (( f_etfs3 )); then
    #
    # ETFS acts like an ethernet bridge: src/dst ethernet addresses do
    # not change. Therefore, dst mac from one interface must be src
    # mac of the other.
    #
    cat > $CFG <<EOF
- port_limit    : 2
  version       : 2
  low_end       : false
  c             : ${o_cores}
  interfaces    : ["$TREX_PORTID0", "$TREX_PORTID1"]
  port_info     :
                 - src_mac  : ${testbed_macaddr[${this_host}-0]}
                   dest_mac : ${testbed_macaddr[${this_host}-1]}
                 - src_mac  : ${testbed_macaddr[${this_host}-1]}
                   dest_mac : ${testbed_macaddr[${this_host}-0]}
EOF
elif (( f_use_ipv6 )); then
    cat > $CFG <<EOF
- port_limit    : 2
  version       : 2
  low_end       : false
  c             : ${o_cores}
  interfaces    : ["$TREX_PORTID0", "$TREX_PORTID1"]
  port_info     :
                 - src_mac  : ${testbed_macaddr[${this_host}-0]}
                   dest_mac : ${testbed_macaddr[${servers[0]}-0]}
                 - src_mac  : ${testbed_macaddr[${this_host}-1]}
                   dest_mac : ${testbed_macaddr[${servers[1]}-0]}
EOF
elif (( f_use_ipv6 )); then
    # Try only using MAC for IPv4, this fails on RDMA TREX w/core too bad.
    if (( f_use_native_mac )); then
        declare dest_mac0="${testbed_macaddr[${servers[0]}-native-0]}"
        declare dest_mac1="${testbed_macaddr[${servers[1]}-native-0]}"
    else
        declare dest_mac0="${testbed_macaddr[${servers[0]}-0]}"
        declare dest_mac1="${testbed_macaddr[${servers[1]}-0]}"
    fi
    cat > $CFG <<EOF
- port_limit    : 2
  version       : 2
  low_end       : false
  c             : ${o_cores}
  interfaces    : ["$TREX_PORTID0", "$TREX_PORTID1"]
  port_info     :
                 - src_mac  : ${testbed_macaddr[${this_host}-0]}
                   dest_mac : ${dest_mac0}
                 - src_mac  : ${testbed_macaddr[${this_host}-1]}
                   dest_mac : ${dest_mac1}
EOF
else
    declare gw0id=${nic0_intf_ip%%.*}
    declare gw1id=${nic1_intf_ip%%.*}
    cat > $CFG <<EOF
- port_limit    : 2
  version       : 2
  low_end       : false
  c             : ${o_cores}
  interfaces    : ["$TREX_PORTID0", "$TREX_PORTID1"]
  port_info     :
                 - ip         : $nic0_intf_ip
                   default_gw : $gw0id.$gw0id.$gw0id.$gw0id
                 - ip         : $nic1_intf_ip
                   default_gw : $gw1id.$gw1id.$gw1id.$gw1id
EOF
fi

# Run the trex server
cat $CFG
echo "Starting TREX on testbed $TESTBED"

set -x

if (( ! f_etfs3 )); then
    arprefresh=$((60 * 60 * 24 * 30))
    arparg="--arp-refresh-period $arprefresh"
fi
if (( f_use_ipv6 )); then
    ipv6arg="--ipv6"
fi

while ! $SUDO ./t-rex-64 --cfg $CFG $v_flag --no-termio --no-scapy-server --iom 0 $arparg $ipv6arg -i ; do
    echo "TREX startup failed, retry in 1 second"
    sleep 1
done

#python /trex/automation/trex_control_plane/server/trex_server.py -t /trex
#trexid=$!
#wait $trexidid

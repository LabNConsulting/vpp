#!/bin/bash
#
# March 27 2020, Christian E. Hopps <chopps@labn.net>
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
#

if [[ -z "$VPPDIR" ]]; then
    VPPDIR=/usr
fi
if [[ -e $VPPDIR/build-root/install-vpp-native/vpp/bin/vpp ]]; then
    export VPPBLDROOT=$VPPDIR/build-root/install-vpp-native/vpp
    export VPPEXTROOT=$VPPDIR/build-root/install-vpp-native/external
elif [[ -e $VPPDIR/build-root/install-vpp_debug-native/vpp/bin/vpp ]]; then
    export VPPBLDROOT=$VPPDIR/build-root/install-vpp_debug-native/vpp
    export VPPEXTROOT=$VPPDIR/build-root/install-vpp_debug-native/external
elif [[ -e $VPPDIR/bin/vpp ]]; then
    export VPPBLDROOT=$VPPDIR
    export VPPEXTROOT=$VPPDIR
fi
if [[ "${VPPBLDROOT}" != "${VPPDIR}" ]]; then
    # This is running out of a source directory
    export VPPPATH=$VPPBLDROOT/bin
    export VPPPLUGINS=$VPPBLDROOT/lib/vpp_plugins
    export VPPLDPATH=$VPPBLDROOT/lib:$VPPEXTROOT/lib
else
    # This is running out of a binary install (i.e., /usr)
    export VPPPATH=$VPPBLDROOT/bin
    export VPPPLUGINS=$VPPBLDROOT/lib/vpp_plugins
    # export VPPLDPATH=$VPPBLDROOT/lib
fi

vppctl="sudo $VPPPATH/vppctl"
vppstats="sudo $VPPPATH/vpp_get_stats"

get_value () {
    echo $1 | awk '{
    input=$1
    base=1000
    if (index("i", substr(input, length(input)))) {
        input=substr(input, 1, length(input)-1)
        base=1024
    }
    ex = index("KMGTPEZY", substr(input, length(input)))
    if (ex == 0) {
        ex = index("kmgtpezy", substr(input, length(input)))
        base=1024
    }
    if (ex) {
        input=substr(input, 1, length(input)-1)
    }
    prod = input * base^(ex)
    sum += prod
}
END {printf("%d", sum);}'
}

is_in_list() {
    local find=$1; shift
    for elt in $*; do
        if [[ "$find" == "$elt" ]]; then
            return 0
        fi
    done
    return 1
}

pow2ceil() {
    echo $1 | awk '{v=log($1)/log(2); printf("%d\n", v == int(v) ? v : int(v) + 1);}'
}

get_pci_driver () {
    local pcidev=0000:${1#0000:}
    echo $(basename $(readlink /sys/bus/pci/devices/$pcidev/driver))
}

get_pci_pf_device () {
    local pcidev=0000:${1#0000:}
    if [[ -e /sys/bus/pci/devices/$pcidev/physfn ]]; then
        echo $(basename $(readlink /sys/bus/pci/devices/$pcidev/physfn))
    else
        echo
    fi
}

get_pci_vf_number () {
    local vfdev=""
    local pcidev=0000:${1#0000:}
    local phydev=$(get_pci_pf_device $pcidev)
    if [[ $phydev ]]; then
        for ((i=0; i<256; i++)); do
            if [[ ! -e /sys/bus/pci/devices/$phydev/virtfn$i ]]; then
                break
            fi
            vfdev=$(basename $(readlink /sys/bus/pci/devices/$phydev/virtfn$i))
            if [[ $vfdev == $pcidev ]]; then
                echo $i
                break
            fi
        done
    fi
}

convert_v4_v32 () {
    declare -a quads=(${1//\./ })
    local quadlen=${#quads[@]}
    for ((i=$quadlen; i < 4; i++)); do
        quads+=(0)
    done
    echo $(((${quads[0]} << 24) + (${quads[1]} << 16) + (${quads[2]} << 8) + ${quads[3]}))
}

convert_v4_hex () {
    local val32=$(convert_v4_v32 $1)
    printf "%04x:%04x\n" $((val32 >> 16)) $((val32 & 0xFFFF))
}

make_v6_addr () {
    local v6part=":"
    if (( $# > 1 )); then
        v6part=$1; shift
    else
        v6part="2001:"
    fi
    local v4part=$1
    printf "${v6part}:$(convert_v4_hex $v4part)\n"
}

make_v6_prefix () {
    local v6part=":"
    if (( $# > 1 )); then
        v6part=$1; shift
    else
        v6part="2001:"
    fi
    local v4addr=${1%/*}
    local v4plen=${1#*/}
    echo "$(make_v6_addr $v6part $v4addr)/$((v4plen + 96))"
}

make_v4v6_tfs_addr () {
    if (( f_use_ipv6_encap )); then
        make_v6_addr "2001:" $*
    else
        echo $*
    fi
}

make_v4v6_tfs_prefix () {
    if (( f_use_ipv6_encap )); then
        make_v6_prefix "2001:" $*
    else
        echo $*
    fi
}

make_v4v6_user_addr () {
    if (( f_use_ipv6 )); then
        make_v6_addr "2100:" $*
    else
        echo $*
    fi
}

make_v4v6_user_prefix () {
    if (( f_use_ipv6 )); then
        make_v6_prefix "2100:" $*
    else
        echo $*
    fi
}

set_pci_num_sriov () {
    local pcidev=0000:${1#0000:}
    local nsriov=$2
    echo $nsriov | sudo tee /sys/bus/pci/devices/$pcidev/sriov_numvfs > /dev/null
}

get_pci_ifname () {
    local pcidev=0000:${1#0000:}
    ls /sys/bus/pci/devices/$pcidev/net
}

unbind_pci_device () {
    local pcidev=0000:${1#0000:}
    echo $pcidev | sudo tee /sys/bus/pci/devices/$pcidev/driver/unbind > /dev/null
}

bind_pci_device () {
    local pcidev=0000:${1#0000:}
    local driver=$2
    echo $driver | sudo tee /sys/bus/pci/devices/$pcidev/driver_override > /dev/null
    echo $pcidev | sudo tee /sys/bus/pci/drivers/$driver/bind > /dev/null
    echo | sudo tee /sys/bus/pci/devices/$pcidev/driver_override > /dev/null
}

get_mac_address() {
    ip link show dev $1 | awk '/^ *link\/ether/{print $2}'
}

setup_avf () {
    local host=$1
    local pcidev=$2
    local mac=$3

    local pfpcidev=${testbed_pci_parents[$host,$pcidev]}
    if [[ -z "$pfpcidev" ]]; then
        echo "No parent for avf interface $pcidev"
        exit 1
    fi

    local pfdriver=$(get_pci_driver $pfpcidev)
    if [[ -z "$pfdriver" ]]; then
        echo "No parent driver"
        exit 1
    fi
    if [[ $pfdriver != "i40e" ]]; then
        unbind_pci_device $pfpcidev
        bind_pci_device $pfpcidev i40e
    fi

    set_pci_num_sriov $pfpcidev 0
    set_pci_num_sriov $pfpcidev 1

    local pfifname=$(get_pci_ifname $pfpcidev)
    # local _vfnum=$(get_pci_vf_number $pcidev)
    local vfnum=0
    # sudo ip link set $pfifname vf ${vfnum} down
    sudo ip link set $pfifname vf ${vfnum} mac ${mac}
    sudo ip link set $pfifname vf ${vfnum} trust on

    unbind_pci_device $pcidev
    bind_pci_device $pcidev vfio-pci
}

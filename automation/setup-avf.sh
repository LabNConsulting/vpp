#!/bin/bash -x

export VPPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
source $VPPDIR/automation/setup.sh
source $VPPDIR/automation/tfs-setup.sh

setup_avf_interface() {
    local ifname=$1
    if [[ ${testbed_interfaces[$ifname]} =~ avf-0 || ${testbed_interfaces[$ifname]} =~ VirtualFunctionEthernet ]]; then
        if [[ ${testbed_interfaces[$ifname]} =~ avf-0 ]]; then
            declare _dev="${testbed_interfaces[$ifname]/avf-0\//} "
        else
            declare _dev="${testbed_interfaces[$ifname]/VirtualFunctionEthernet/} "
        fi
        declare _pcidevbus=${_dev%%/*}
        declare _pcidevslot=${_dev%/*}; _pcidevslot=${_pcidevslot#*/}
        declare _pcidevfn=${_dev##*/}
        declare _pcidev=$(printf "0000:%02x:%02x.%x" 0x$_pcidevbus 0x$_pcidevslot 0x$_pcidevfn)
        setup_avf $host $_pcidev ${testbed_macaddr[${host}-$i]}
    fi
}

setup_docker_interfaces() {
    local hosts="${testbed_servers[$TESTBED]} ${testbed_trex[$TESTBED]}"
    local devices host
    for host in ${hosts}; do
        declare devices=""
        for ((i=0; i<2; i++)); do
            setup_avf_interface $host-$i
        done
    done
}

if is_in_list $TESTBED "${testbed_docker_physical[@]}"; then
    setup_docker_interfaces
else
    setup_avf_interface $HOSTNAME-native-0
    setup_avf_interface $HOSTNAME-native-1
fi

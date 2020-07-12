#!/bin/bash
#
# March 27 2020, Christian E. Hopps <chopps@labn.net>
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
HOSTNAME=${HOSTNAME:=$(hostname)}

# =================
# Get Testbed Data.
# =================

# Keys in dict
# jq  -r ".$arr"' | to_entries | .[].key' < testbed_data.json
#  entries in value if list, fails if not list
# jq  -r ".$arr"'["A"] | .[]' < testbed_data.json
# entries in value separated by space
# jq  -c -r ".$arr"'["A"] | join(" ")' < testbed_data.json
# source <(python3 $VPPDIR/automation/testbed_data.py)

source $VPPDIR/automation/bash2json.sh

# Get the testbed given the hostname
for _tbname in ${!testbed_servers[@]}; do
    [[ ${testbed_servers[$_tbname]} =~ $HOSTNAME ]] && TESTBED=$_tbname && break
done
if [[ -z "$TESTBED" ]]; then
    for _tbname in ${!testbed_trex[@]}; do
        [[ "${testbed_trex[$_tbname]}" = "$HOSTNAME" ]] && TESTBED=$_tbname && break
    done
fi

# --------------------
# Generate Config Data
# --------------------

_ipid=11
other_host=""
this_host="$HOSTNAME"
trex_host=${testbed_trex[$TESTBED]}

if [[ "${this_host}" == "${trex_host}" ]]; then
    :
else
    # master is first server in list
    for _server in ${testbed_servers[$TESTBED]}; do
        if [[ $_server == $this_host ]]; then
            export IPID=$_ipid
        else
            other_host=$_server
        fi
        _ipid=$((_ipid + 1))
    done
    export NETID=$IPID

    if (( IPID == 11 )); then
        export OTHER_IPID=12
        export OTHER_NETID=12
        masterslave="master"
    else
        export OTHER_IPID=11
        export OTHER_NETID=11
        masterslave="slave"
    fi

    export THIS_PREIP=$NETID.$NETID.$NETID
    export THIS_IP=$THIS_PREIP.$IPID
    export OTHER_PREIP=$OTHER_NETID.$OTHER_NETID.$OTHER_NETID
    export OTHER_IP=$OTHER_PREIP.$OTHER_IPID
    export PKTGEN_IP=${THIS_PREIP}.253 # different from etfs
    export OPKTGEN_IP=${OTHER_PREIP}.253 # different from etfs

    # This is standard for cisco trex
    if [[ "$IPID" == "11" ]]; then
        export LOCAL_TREX_PREIP=16.0.0
        export LOCAL_TREX_NETS=${LOCAL_TREX_PREIP}.0/24
        export REMOTE_TREX_PREIP=48.0.0
        export REMOTE_TREX_NETS=${REMOTE_TREX_PREIP}.0/24
    else
        export LOCAL_TREX_PREIP=48.0.0
        export LOCAL_TREX_NETS=${LOCAL_TREX_PREIP}.0/24
        export REMOTE_TREX_PREIP=16.0.0
        export REMOTE_TREX_NETS=${REMOTE_TREX_PREIP}.0/24
    fi

    user_intf_addr=$THIS_IP/24
    user_intf_ip=${user_intf_addr%/*}

    export USEIF_PREIP=13.13
    export USEIF_POSTIP=$IPID.1
    iptfs_intf_addr=${USEIF_PREIP}.$USEIF_POSTIP/16
    iptfs_intf_ip=${iptfs_intf_addr%/*}

    this_mac=${testbed_macaddr[${this_host}-1]}
    other_mac=${testbed_macaddr[${other_host}-1]}
    if [[ "$IPID" == "11" ]]; then
        trex_mac=${testbed_macaddr[${trex_host}-0]}
    else
        trex_mac=${testbed_macaddr[${trex_host}-1]}
    fi
    get_tfs_intf_addr() {
        local c=$1
        local nc=$2
        local ip=$((1 + c * (256 / nc)))
        echo "${USEIF_PREIP}.${IPID}.${ip}/16"
    }
    get_tfs_local_ip() {
        local c=$1
        local nc=$2
        local ip=$((1 + c * (256 / nc)))
        echo "${USEIF_PREIP}.${IPID}.${ip}"
    }
    get_tfs_remote_ip() {
        local c=$1
        local nc=$2
        local ip=$((1 + c * (256 / nc)))
        echo "${USEIF_PREIP}.${OTHER_IPID}.${ip}"
    }
    get_tfs_local_range_start() {
        local c=$1
        local nc=$2
        local ipid=$((c * (256 / nc)))
        echo "${USEIF_PREIP}.${IPID}.${ipid}"
    }
    get_tfs_remote_range_start() {
        local c=$1
        local nc=$2
        local ipid=$((c * (256 / nc)))
        echo "${USEIF_PREIP}.${OTHER_IPID}.${ipid}"
    }
    get_tfs_local_range_end() {
        local c=$1
        local nc=$2
        local ipid=$(((c + 1) * (256 / nc) - 1))
        echo "${USEIF_PREIP}.${IPID}.${ipid}"
    }
    get_tfs_remote_range_end() {
        local c=$1
        local nc=$2
        local ipid=$(((c + 1) * (256 / nc) - 1))
        echo "${USEIF_PREIP}.${OTHER_IPID}.${ipid}"
    }
fi

#!/bin/bash -x
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

BR=br0
NIC0=eth0
NIC1=eth1

# Setup the bridge
ip route del default || true
brctl addbr $BR
ifconfig $BR up
for f in $NIC0 $NIC1; do
    declare ethx_addr=$(ip -4 addr show $f | awk '/inet /{print $2}')
    [[ -z "$ethx_addr" ]] || ip addr del $ethx_addr dev $NIC0
    brctl addif $BR $f
    bridge -d link set dev $f learning off
done

usage () {
    cat << EOF
$0: [-d us-delay [-j jitter-pct] [-l loss-pct]]"

    count, rate, szie :: accepts "K" "Ki" and "k", KMGTPEZY are 1000 based otherwise 1024

    -d us-delay :: delay in microseconds
EOF
    exit 0
}

o_delay=
o_loss=
o_loss_correlation="25"
o_jitter=
o_jitter_correlation="10"
o_rate=
while getopts d:J:j:L:l:r: opt; do
    case $opt in
    d)
        o_delay=${OPTARG}
        ;;
    j)
        o_jitter=${OPTARG}
        ;;
    J)
        o_jitter_correlation=${OPTARG}
        ;;
    l)
        o_loss=${OPTARG}
        ;;
    L)
        o_loss_correlation=${OPTARG}
        ;;
    r)
        o_rate=$(get_value ${OPTARG})
    esac
done
shift $(($OPTIND - 1))

declare qdisc_args=""
if [[ "$o_delay" ]]; then
    qdisc_args+=" delay ${o_delay}usec"
fi
if [[ "${o_jitter}" ]]; then
    if [[ ! "$o_delay" ]]; then
        usage
    fi
    qdisc_args+=" ${o_jitter}usec ${o_jitter_correlation}%"
fi
if [[ "${o_loss}" ]]; then
   if [[ ! "$o_delay" ]]; then
       usage
   fi
   qdisc_args+=" loss ${o_loss}% ${o_loss_correlation}%"
fi
if [[ "${o_rate}" ]]; then
    qdisc_args+=" rate ${o_rate}"
fi
for f in $NIC0 $NIC1; do
    echo "== Adding $args to intefrace qdisc's"
    tc qdisc del dev ${f} root
    tc qdisc add dev ${f} root handle 1:0 netem $qdisc_args
    tc qdisc show dev ${f}
done

# Maybe we could print out some stats or something
touch /tmp/bridge-done
tail -f /dev/null

#!/bin/bash
#
# June 16 2020, Christian Hopps <chopps@labn.net>
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
export AUTODIR="$VPPDIR/automation"

handler () {
    echo "Exiting due to ^C"
    exit 1
}

trap handler INT

set -ex

topdir=/tmp/timing-result
if [[ -d $topdir ]]; then
    echo "Archive/remove $topdir and rerun"
    exit 1
fi

export TESTBED=B
source $VPPDIR/automation/timing-setup.sh
capture_port=$tfs_capture_intf

COMMON="--event-log-size=30M --log-replace --capture-port=${capture_port} --capture-snaplen=64 --testbed=$TESTBED"
#for mrate in 10 100 500 1000 2000 5000; do
#for mrate in 10 100 1000 2000; do
for mrate in 10 100 1000 2000 5000; do
    # if (( mrate < 1000 )); then
    #     dur=10
    # elif (( mrate < 2000 )); then
    #     dur=5
    # else
    #     dur=2
    # fi
    # Anything more than 2 seconds is just making graphs hard to read
    dur=2
    rate=$(( mrate * 1000000 ))
    for pct in 0 50 100; do
        i=0
        for ((i=0; i<10; i++)); do
            logdir=$topdir/imix-${mrate}-${pct}
            $AUTODIR/runtests.py $COMMON -d $dur -r ${mrate}M --logdir=$logdir -p $pct test_verify_timing.py
            pcaplog="${logdir}/${tfs_capture_fname%.pcap.gz}.log"
            # Don't expect no drops for anything above 5G
            if (( mrate > 5000 )); then
                break
            fi
            drops=$(sed -E -e '/ISB_IFDROP/!d;s/.*ISB_IFDROP: (\d*)/\1/' < $pcaplog)
            if (( ! drops )); then
                break
            fi
            echo "WARNING: Re-running due to capture drops ($drops)"
        done
        if (( i==10 )); then
            echo "ERROR: Failed to get non-drop run after 10 retries"
        fi
        # We only need a single no traffic case
        if (( pct == 0 )); then
            continue
        fi
        for psize in 40 1500; do
            i=0
            for ((i=0; i<10; i++)); do
                logdir=$topdir/pkt-${psize}-${mrate}-${pct}
                $AUTODIR/runtests.py $COMMON -d $dur -U ${psize} -r ${mrate}M --logdir=$logdir -p $pct test_verify_timing.py
                pcaplog="${logdir}/${tfs_capture_fname%.pcap.gz}.log"
                # Don't expect no drops for anything above 5G
                if (( mrate > 5000 )); then
                    break
                fi
                drops=$(sed -E -e '/ISB_IFDROP/!d;s/.*ISB_IFDROP: (\d*)/\1/' < $pcaplog)
                if (( ! drops )); then
                    break
                fi
                echo "WARNING: Re-running due to capture drops ($drops)"
            done
            if (( i==10 )); then
                echo "ERROR: Failed to get non-drop run after 10 retries"
            fi
        done
    done
done

# for logdir in $topdir/traffic-*; do
#     (cd $logdir
#      for d in $(ls -d chopps-T\=B-r\=*); do
#          d1=$(echo $d | sed -e 's/chopps-T=B-r=//;s/-.*//')
#          d1=${d1%-.*}
#          d1=$(( d1 / 1000000 ))
#          tshark  -r $d/*.pcap.gz | awk 'BEGIN {last=0;} {printf("%d\t%f\t%f\n", $1, $2, $2-last); last=$2;}' > ${d1}M.csv
#      done
#     )
# done

#!/bin/bash
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

# These options yield better visibility of errors than -q without
# showing extraneous info. Also: don't die because of new host key
SSHOPTS="-o StrictHostKeyChecking=accept-new -o LogLevel=error"

export VPPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd -P .. && pwd )"

HOSTNAME=$(hostname)

if [[ -n "$1" ]]; then
    VPPDIR=$(realpath $1)
fi

declare LABDATA=/etc/vpp-lab-data/testbed_data.json
if [[ ! -e $LABDATA ]]; then
    echo "Cannot sync, lab machines without $LABDATA file"
    exit 1
fi

declare _lab_machines=($(jq -r 'select(.testbed_machines) | .testbed_machines[]' < $LABDATA))
if (( ! ${#_lab_machines[@]} )); then
    echo "Cannot sync, testbed_machines is empty in $LABDATA file"
    exit 1
fi

declare -a sync_machines
declare this_machine
for _m in "${_lab_machines[@]}"; do
    if [[ "$_m" == "$HOSTNAME" ]]; then
        this_machine="$_m"
    else
        sync_machines+=("$_m")
    fi
done
if [[ ! "$this_machine" ]]; then
    echo "Cannot sync, this machine $HOSTNAME not found in lab machines"
    exit 1
fi
if [[ ! "${sync_machines[@]}" ]]; then
    echo "Cannot sync, no machines found to sync to"
    exit 1
fi
if [[ ! -d ${VPPDIR}/.git ]]; then
    echo "$0: ${VPPDIR} doesn't seem to be a git repo"
    exit 1;
fi


#
# verify reachability
#
declare -a machines deadmachines
for m in "${sync_machines[@]}"; do
    if ssh ${SSHOPTS} $m true; then
	machines+=("$m")
    else
	deadmachines+=("$m")
	echo "*** WARNING: skipping unreachable host $m"
    fi
done

echo "RSYNC-REPO: Syncing ${VPPDIR} on ${machines[*]}"
declare -a pids
declare -A mpids
for m in "${machines[@]}"; do
    echo "$m"
    ssh ${SSHOPTS} "$m" mkdir -p ${VPPDIR}
    (set -o pipefail;
     rsync -a --info=stats1 -e 'ssh -o StrictHostKeyChecking=accept-new -o LogLevel=error' \
           ${VPPDIR}/ "$m:${VPPDIR}/" --delete | \
         sed -e "/^$/d;s/^/$m: /") &
    pids+=($!)
    mpids[$!]=$m
done

rstatus=0
for pid in ${pids[*]}; do
    wait ${pid}
    status=$?
    if (( status > 0 )); then
        echo ${mpids[$pid]} exited with: $status
        rstatus=1
    else
        # echo "RSYNC-REPO: SYNCED: ${mpids[$pid]}"
        :
    fi
done

#
# print warnings again at the end for visibility
#
for m in ${deadmachines[*]}; do
    echo "*** WARNING: skipped unreachable host $m"
done

exit $rstatus

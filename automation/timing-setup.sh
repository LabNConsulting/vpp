#!/bin/bash
#
# October 7 2020, Christian Hopps <chopps@labn.net>
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
source $VPPDIR/automation/bash2json.sh
HOSTNAME=${HOSTNAME:=$(hostname)}

# Get the capture ports
# we capture traffic from the first machine in the testbed
declare -a servers=(${testbed_servers[$TESTBED]})
user_intf="${servers[0]}-0"
tfs_intf="${servers[0]}-1"

echo "CP: ${!testbed_unix_interfaces[@]}"
declare -a capture_ports=(${!testbed_unix_interfaces[@]})
echo "CP: ${capture_ports[*]}"

declare user_capture_port tfs_capture_port
# Find HW timestamping port for TFS
for port in "${capture_ports[@]}"; do
    if [[ "$testbed_hw_timestamp_interfaces" =~ "$port" ]]; then
        tfs_capture_port=$port
        break
    fi
done
if [[ -z "$tfs_capture_port" ]]; then
    echo "Warning: no HW timestamping port found for TFS capture"
    tfs_capture_port=${capture_ports[0]}
fi
for port in "${capture_ports[@]}"; do
    if [[ "$port" != "$tfs_capture_port" ]]; then
        user_capture_port=$port
        break
    fi
done
if [[ -z "$user_capture_port" || -z "$tfs_capture_port" ]]; then
   echo "Can't find capture ports for user and tfs interfaces"
   exit 1
fi

user_capture_host=${user_capture_port%-[0-9]}
user_capture_intf=${testbed_unix_interfaces[$user_capture_port]}
if [[ "$user_capture_host" != "$HOSTNAME" ]]; then
    user_capture_fname="pcap-server-${user_capture_intf}-${user_capture_host}.pcap.gz"
    user_capture_intf=${user_capture_host}:${user_capture_intf}
else
    user_capture_fname="pcap-server-${user_capture_intf}.pcap.gz"
fi

tfs_capture_host=${tfs_capture_port%-[0-9]}
tfs_capture_intf=${testbed_unix_interfaces[$tfs_capture_port]}
if [[ "$tfs_capture_host" != "$HOSTNAME" ]]; then
    tfs_capture_fname="pcap-server-${tfs_capture_intf}-${tfs_capture_host}.pcap.gz"
    tfs_capture_intf=${tfs_capture_host}:${tfs_capture_intf}
else
    tfs_capture_fname="pcap-server-${tfs_capture_intf}.pcap.gz"
fi

# Configure switch automatically here eventually.
# mirror-port ethernet ${testbed_switchports[$user_capture_port]}
# mirror-port ethernet ${testbed_switchports[$tfs_capture_port]}

# user mon out on the switchport (i.e., to this server interface)
# interface ethernet ${testbed_switchports[$user_intf]}
# mon ethernet ${testbed_switchports[$user_capture_port]} out

# tfs mon in on the switchport (i.e., from this server interface)
# interface ethernet ${testbed_switchports[$tfs_intf]}
# mon ethernet ${testbed_switchports[$tfs_capture_port]} out

#!/bin/bash
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

set -e

# --------
# Defaults
# --------
run_gdb=0

iptfs_enable=yes
iptfs_congestion_control=no
iptfs_dont_fragment=no
iptfs_ether_rate=10G
iptfs_max_latency=10000
iptfs_packet_size=1500

ike_proposals=aes256gcm16-prfsha1-modp2048
esp_proposals=aes256gcm16-prfsha1
ike_reauth=6000m
ike_rekey=600m
esp_rekey=30m
o_connections=1

f_in_container=0

usage () {
    cat << EOF
$0: [-cCDghnN] [-k esp-rekey] [-K ike-rekey] [-l latency] [-m count] [-r rate] [-R ike-reauth] [-s size]"

    count, rate, szie :: accepts "K" "Ki" and "k", KMGTPEZY are 1000 based otherwise 1024

    -c :: use congestion control
    -C :: in container [${f_in_container}]
    -D :: require don't fragment
    -g :: run with GDB
    -k duration :: ESP rekey time
    -K duration :: IKE rekey time
    -g :: run with GDB
    -l latency :: maximum latency (usecs) for user traffic [${iptfs_max_latency}]
    -m count :: number of connections for m-p2p
    -n :: use NULL encryption and authentication
    -N :: no iptfs (ipsec only)
    -r rate :: the ethernet rate of the iptfs tunnel [${iptfs_ether_rate}]
    -R duration :: IKE reauth time
    -s size :: the L3 packet size of IPTFS packets [${iptfs_packet_size}]
EOF
    exit 0
}

while getopts CcDghk:K:l:m:nNr:R:s:t: opt; do
    case $opt in
        C)
            f_in_container=1
            ;;
        c)
            iptfs_congestion_control=yes
            ;;
        D)
            iptfs_dont_fragment=yes
            ;;
        g)
            run_gdb=1
            ;;
        k)
            esp_rekey=${OPTARG}
            ;;
        K)
            ike_rekey=${OPTARG}
            ;;
        l)
            iptfs_max_latency="$OPTARG"
            ;;
        m)
            o_connections=${OPTARG}
            ;;
        n)
            esp_proposals=null
            ike_proposals=null
            ;;
        N)
            iptfs_enable=no
            ;;
        R)
            ike_reauth=${OPTARG}
            ;;
        r)
            iptfs_ether_rate=${OPTARG}
            ;;
        s)
            iptfs_packet_size=${OPTARG}
            ;;
        t)
            trace="${OPTARG}"
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

o_connections=$(get_value $o_connections)
iptfs_ether_rate=$(get_value $iptfs_ether_rate)
iptfs_max_latency=$(get_value $iptfs_max_latency)
iptfs_packet_size=$(get_value $iptfs_packet_size)

#
# Set a bunch of environment variables based on where we are running.
#
source $VPPDIR/automation/tfs-setup.sh

if (( f_in_container )); then
    swanetc=/tmp/etc-swan
else
    swanetc=/tmp/etc-swan-${USER}
fi
mkdir -p ${swanetc}
cp -pr ${VPPBLDROOT}/etc/strongswan.conf ${swanetc}
cp -pr ${VPPBLDROOT}/etc/strongswan.d  ${swanetc}
cp -pr ${VPPBLDROOT}/etc/swanctl ${swanetc}
swandir=${swanetc}/strongswan.d
swanctldir=${swanetc}/swanctl
export STRONGSWAN_CONF=${swanetc}/strongswan.conf

cat > ${swandir}/vpp.conf <<EOF
charon {
    # Very important so we have access over ssh mapped socket to the vici socket.
    group = vpp
    filelog {
        stderr {
            time_format = %b %e %T
            ike_name = yes
            default = 1
            flush_line = yes

            ike = 3
            net = 4
            cfg = 1
            lib = 4
            knl = 4
        }
    }
    syslog {
        identifier = charon-custom
        daemon {
        }
        auth {
            default = -1
            ike = 0
        }
    }
    plugins {
        socket-vpp { path = /tmp/strongswan-ike-punt.sock }
        socket-default { load = no }
        kernel-netlink { load = no }
        kernel-libipsec { load = no }
        kernel-pfroute { load = no }
    }
}
EOF


# Return the masklen given a connection count (must be power of 2)
get_masklen () {
    echo $((23 + $1))
}

# return network increment given a connection count (must be power # of 2)
get_netinc () {
    echo $((2 ** (9-$1)))
}

echo "connections {" > ${swanctldir}/conf.d/vpp.conf

declare o_conlog2=$(awk "BEGIN{print log($o_connections)/log(2);}")
declare ML=$((24 + o_conlog2))
declare INC=$((2 ** (8 - o_conlog2)))
declare LAST=0
for ((i=0; i < o_connections; i++)); do
    cat >> ${swanctldir}/conf.d/vpp.conf <<EOF
    net-${i} {
        mobike=no
        version=2
        reauth_time = ${ike_reauth}
        rekey_time = ${ike_rekey}
        local_addrs=$(make_v4v6_tfs_addr $(get_tfs_local_ip $i $o_connections))
        remote_addrs=$(make_v4v6_tfs_addr $(get_tfs_remote_ip $i $o_connections))
        proposals = ${ike_proposals}
        local {
            id = user-${IPID}
            auth=psk
        }
        remote {
            id = user-${OTHER_IPID}
            auth=psk
        }
        children {
            vpp$((i + 1)) {
                local_ts=$(make_v4v6_user_prefix ${THIS_PREIP}.${LAST}/${ML}),$(make_v4v6_user_prefix ${LOCAL_TREX_PREIP}.${LAST}/${ML})
                remote_ts=$(make_v4v6_user_prefix ${OTHER_PREIP}.${LAST}/${ML}),$(make_v4v6_user_prefix ${REMOTE_TREX_PREIP}.${LAST}/${ML})
                rekey_time = ${esp_rekey}
                esp_proposals = ${esp_proposals}
EOF

# Only include IPTFS config if enabled, this allows testing without the TFS additions
    if [[ "$iptfs_enable" == "yes" ]]; then
        cat >> ${swanctldir}/conf.d/vpp.conf <<EOF
                iptfs = ${iptfs_enable}
                iptfs_cc = ${iptfs_congestion_control}
                iptfs_df = ${iptfs_dont_fragment}
                iptfs_ether_bitrate = ${iptfs_ether_rate}
                iptfs_max_delay = ${iptfs_max_latency}
                iptfs_packet_size = ${iptfs_packet_size}
EOF
    fi

    cat >> ${swanctldir}/conf.d/vpp.conf <<EOF
            }
        }
    }
EOF
    LAST=$((LAST + INC))
done

cat >> ${swanctldir}/conf.d/vpp.conf <<EOF
}
secrets {
    # PSK secret
    ike-1 {
        id-a = user-${IPID}
        id-b = user-${OTHER_IPID}
        secret = 0sv+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL
        secret = 29577a3c6ec833712dd0f614f727a72182c800af1b068b168c2806568c28065
    }
}
EOF

#[--debug-<type> <level>]
#<type>:  log context type (dmn|mgr|ike|chd|job|cfg|knl|net|asn|enc|tnc|imc|imv|pts|tls|esp|lib)
#<level>: log verbosity (-1 = silent, 0 = audit, 1 = control,
#                        2 = controlmore, 3 = raw, 4 = private)

debugflags=""
if [[ -n "$trace" ]]; then
    for t in "$trace"; do
        debugflags="$debugflags --debug-$t=3"
    done
fi

if (( f_in_container )); then
    echo "Starting charon"

    sudo STRONGSWAN_CONF="${STRONGSWAN_CONF}" LD_LIBRARY_PATH="${VPPLDPATH}" ${VPPBLDROOT}/libexec/ipsec/charon $debugflags
elif (( run_gdb )); then
    echo "Starting charon in GDB"
    sudo STRONGSWAN_CONF="${STRONGSWAN_CONF}" LD_LIBRARY_PATH="${VPPLDPATH}" gdb ${VPPBLDROOT}/libexec/ipsec/charon -ex "run $debugflags"
else
    echo "Starting charon"
    sudo STRONGSWAN_CONF="${STRONGSWAN_CONF}" LD_LIBRARY_PATH="${VPPLDPATH}" ${VPPBLDROOT}/libexec/ipsec/charon $debugflags
fi

#
# January 11 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021 LabN Consulting, L.L.C.
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

if (( f_use_etfs )); then
    if (( f_use_macsec && !f_remove )); then
        etfs_encap_macsec_cfg="macsec crypto-alg aes-gcm-256 tx-crypto-key 4a506a794f574265564551694d6537684a506a794f574265564551694d653768"
        etfs_decap_macsec_cfg="stea ${other_mac} macsec crypto-alg aes-gcm-256 rx-crypto-key 4a506a794f574265564551694d6537684a506a794f574265564551694d653768"
    else
        etfs_encap_macsec_cfg=""
        etfs_decap_macsec_cfg=""
    fi

    if [[ $o_tfs_mode ]]; then
        mode_str="tfs-mode $o_tfs_mode"
    fi
    if (( o_connections <= 1 )); then
        if (( f_remove )); then
	    cat >> $vppconfig <<- EOF
etfs3 encap delete rx ${vpp_ifnames[0]}
etfs3 decap delete rx ${vpp_ifnames[1]}
EOF
        else
	    cat >> $vppconfig <<- EOF
etfs3 encap add rx ${vpp_ifnames[0]} tx ${vpp_ifnames[1]} fs ${o_iptfs_packet_size} rate ${o_tfs_ether_rate} maxagg ${o_tfs_max_latency} stea ${this_mac} dtea ${other_mac} ${etfs_encap_macsec_cfg} ${mode_str}
etfs3 decap add rx ${vpp_ifnames[1]} tx ${vpp_ifnames[0]} ${etfs_decap_macsec_cfg}
EOF
        fi
    else
	for ((i=0; i < o_connections; i++)); do
	    vlan=$((100+i))
            if (( f_remove )); then
	        cat >> $vppconfig <<- EOF
etfs3 encap delete rx ${vpp_ifnames[0]}.${vlan}
etfs3 decap delete rx ${vpp_ifnames[1]}.${vlan}
EOF
            else
	        cat >> $vppconfig <<- EOF
etfs3 encap add rx ${vpp_ifnames[0]}.${vlan} tx ${vpp_ifnames[1]}.${vlan} fs ${o_iptfs_packet_size} rate ${o_tfs_ether_rate} maxagg ${o_tfs_max_latency} stea ${this_mac} dtea ${other_mac} ${etfs_encap_macsec_cfg} ${mode_str}
etfs3 decap add rx ${vpp_ifnames[1]}.${vlan} tx ${vpp_ifnames[0]}.${vlan} ${etfs_decap_macsec_cfg}
EOF
            fi
	done
    fi
    if (( f_remove )); then
	echo "set int promiscuous off ${vpp_ifnames[0]}"  >> $vppconfig
    else
	echo "set int promiscuous on ${vpp_ifnames[0]}"  >> $vppconfig
    fi
elif (( f_use_ike )); then
    if (( f_remove )); then
        echo "ip route delete ${LOCAL_TREX_NETS} via ${PKTGEN_IP}" >> $vppconfig
    else
        echo "ip route add ${LOCAL_TREX_NETS} via ${PKTGEN_IP}" >> $vppconfig
    fi
else
    if (( f_null_crypto )); then
        KEY=""
        CRYPTO_ALG="crypto-alg none"
        INTEG_ALG="integ-alg none"
        IF_CRYPTO_CONFIG="${INTEG_ALG} ${CRYPTO_ALG}"
        POLICY_CRYPTO_CONFIG="${INTEG_ALG} ${CRYPTO_ALG}"
        LOCALSPI=1112
        REMOTESPI=1211
    else
        KEY="4a506a794f574265564551694d6537684a506a794f574265564551694d653768"
        CRYPTO_ALG="crypto-alg aes-gcm-256"
        INTEG_ALG=""
        IF_CRYPTO_CONFIG="local-crypto-key ${KEY} remote-crypto-key ${KEY} ${CRYPTO_ALG}"
        POLICY_CRYPTO_CONFIG="crypto-key ${KEY} ${CRYPTO_ALG}"
        LOCALSPI=$(printf "%u" 0xBBBBBBBB)
        REMOTESPI=$(printf "%u" 0xCCCCCCCC)
    fi

    if (( IPID == 12 )); then
        tmpspi=$LOCALSPI
        LOCALSPI=$REMOTESPI
        REMOTESPI=$tmpspi
    fi

    udp_encap_flag=""
    if (( f_use_udp )); then
        udp_encap_flag="udp-encap"
    fi

    if (( f_use_iptfs )); then
        if (( ! f_use_chaining )); then
            #chaining_arg="iptfs-decap-chaining"
            chaining_arg=""
        else
            chaining_arg="iptfs-use-chaining"
        fi
        if (( f_cc )); then
            tfs_type="iptfs-cc"
        else
            tfs_type="iptfs-nocc"
        fi
        IN_IPTFS_CONFIG="tfs ${tfs_type} ${chaining_arg} iptfs-no-pad-trace"
        IPTFS_CONFIG="tfs ${tfs_type} iptfs-ethernet-bitrate ${o_tfs_ether_rate} iptfs-mtu ${o_iptfs_packet_size} iptfs-max-delay-us ${o_tfs_max_latency} ${chaining_arg} iptfs-no-pad-trace"
        if (( f_no_pad )); then
            IPTFS_CONFIG+=" iptfs-no-pad-only"
        fi
        if [[ $o_tfs_mode ]]; then
            IPTFS_CONFIG+=" iptfs-mode ${o_tfs_mode}"
        fi
    fi

    if (( f_use_policy )); then
        if (( ! f_remove )); then
            echo "ipsec spd add 1" >> $vppconfig
        fi
    fi
    declare o_conlog2=$(pow2ceil $o_connections)
    declare ML=$((24 + o_conlog2))
    declare INC=$((256 / o_connections))
    declare LAST=0
    for ((i=0; i <o_connections; i++)); do
        declare local_tfs_ip="$(make_v4v6_tfs_addr $(get_tfs_local_ip $i $o_connections))"
        declare remote_tfs_ip="$(make_v4v6_tfs_addr $(get_tfs_remote_ip $i $o_connections))"
        declare local_tfs_ip_range="$(make_v4v6_tfs_addr $(get_tfs_local_range_start $i $o_connections)) - $(make_v4v6_tfs_addr $(get_tfs_local_range_end $i $o_connections))"
        declare remote_tfs_ip_range="$(make_v4v6_tfs_addr $(get_tfs_remote_range_start $i $o_connections)) - $(make_v4v6_tfs_addr $(get_tfs_remote_range_end $i $o_connections))"

        declare local_trex_ip_range="$(make_v4v6_user_addr ${LOCAL_TREX_PREIP}.${LAST}) - $(make_v4v6_user_addr ${LOCAL_TREX_PREIP}.$((LAST + INC - 1)))"
        declare remote_trex_ip_range="$(make_v4v6_user_addr ${REMOTE_TREX_PREIP}.${LAST}) - $(make_v4v6_user_addr ${REMOTE_TREX_PREIP}.$((LAST + INC - 1)))"
        declare this_ip_range="$(make_v4v6_user_addr ${THIS_PREIP}.${LAST}) - $(make_v4v6_user_addr ${THIS_PREIP}.$((LAST + INC - 1)))"
        declare other_ip_range="$(make_v4v6_user_addr ${OTHER_PREIP}.${LAST}) - $(make_v4v6_user_addr ${OTHER_PREIP}.$((LAST + INC - 1)))"

        declare local_trex_ip_prefix="$(make_v4v6_user_prefix ${LOCAL_TREX_PREIP}.${LAST}/${ML})"
        declare remote_trex_ip_prefix="$(make_v4v6_user_prefix ${REMOTE_TREX_PREIP}.${LAST}/${ML})"
        declare other_ip_prefix="$(make_v4v6_user_prefix ${OTHER_PREIP}.${LAST}/${ML})"
        declare pktgen_ip="$(make_v4v6_user_addr ${PKTGEN_IP})"

        if (( f_null_crypto )); then
            declare LOCALSPI=$(($((i + 1))${IPID} * 256))
            declare REMOTESPI=$(($((i + 1))${OTHER_IPID} * 256))
        else
            declare LOCALSPI=$((i + 1))${IPID}
            declare REMOTESPI=$((i + 1))${OTHER_IPID}
        fi

        if (( f_remove )); then
            ADDDEL=del
        else
            ADDDEL=add
        fi

        if [[ "$IPTFS_CONFIG" ]]; then
            if (( f_cc )); then
                extra_outbound_config="iptfs-inbound-sa-id 1${i}"
            fi
        fi

        if (( ! f_use_policy )); then
            if (( ! f_use_tunnel )); then
                cat >> $vppconfig << EOF
ip route $ADDDEL ${local_trex_ip_prefix} via ${pktgen_ip}
ip route $ADDDEL ${other_ip_prefix} via ${remote_tfs_ip}
ip route $ADDDEL ${remote_trex_ip_prefix} via ${remote_tfs_ip}
EOF
            elif (( ! f_use_ipsec )); then
                if (( ! f_remove )); then
                    cat >> $vppconfig << EOF
create ipip tunnel src ${local_tfs_ip} dst ${remote_tfs_ip}
set interface unnumbered ipip${i} use ${vpp_ifnames[1]}
set interface state ipip${i} up
EOF
                fi
                cat >> $vppconfig << EOF
ip route $ADDDEL ${remote_trex_ip_prefix} via ipip${i}
ip route $ADDDEL ${other_ip_prefix} via ipip${i}
ip route $ADDDEL ${local_trex_ip_prefix} via ${pktgen_ip}
EOF
                if (( ! f_remove )); then
                    cat >> $vppconfig << EOF
set interface state ipip${i} down
delete ipip tunnel XXX sw_if_index needed
EOF
                fi
            else
                declare ipsec_intf=ipsec${i}
                if (( !f_remove )); then
                    cat >> $vppconfig << EOF
ipsec itf create instance ${i}
ipsec sa add 1${i} spi ${REMOTESPI} esp ${POLICY_CRYPTO_CONFIG} salt 0x1A2B tunnel-src ${remote_tfs_ip} tunnel-dst ${local_tfs_ip} use-esn use-anti-replay ${udp_encap_flag} inbound ${IN_IPTFS_CONFIG}
ipsec sa add 2${i} spi ${LOCALSPI} esp ${POLICY_CRYPTO_CONFIG} salt 0x1A2B tunnel-src ${local_tfs_ip} tunnel-dst ${remote_tfs_ip} use-esn use-anti-replay ${udp_encap_flag} ${IPTFS_CONFIG} ${extra_outbound_config}
ipsec tunnel protect ${ipsec_intf} sa-in 1${i} sa-out 2${i}
set interface unnumbered ${ipsec_intf} use ${vpp_ifnames[1]}
set interface state ${ipsec_intf} up
EOF
                fi
                cat >> $vppconfig << EOF
ip route $ADDDEL ${remote_trex_ip_prefix} via ${ipsec_intf}
ip route $ADDDEL ${other_ip_prefix} via ${ipsec_intf}
ip route $ADDDEL ${local_trex_ip_prefix} via ${pktgen_ip}
EOF
                if (( f_remove )); then
                    cat >> $vppconfig << EOF
set interface state ${ipsec_intf} down
ipsec tunnel protect ${ipsec_intf} del
ipsec itf delete ${ipsec_intf}
ipsec sa del 2${i}
ipsec sa del 1${i}
EOF
                fi
            fi
        else
            # This is what IKE does right now.. but we want it to be more precise
            # ipsec policy add spd 1 priority 10 inbound action bypass protocol 50 local-ip-range 0.0.0.0 - 255.255.255.255 remote-ip-range 0.0.0.0 - 255.255.255.255 local-port-range 0 - 0 remote-port-range 0 - 0
            # ipsec policy add spd 1 priority 10 outbound action bypass protocol 50 local-ip-range 0.0.0.0 - 255.255.255.255 remote-ip-range 0.0.0.0 - 255.255.255.255 local-port-range 0 - 0 remote-port-range 0 - 0
            if (( f_remove )); then
                cat >> $vppconfig << EOF
ip route del ${remote_trex_ip_prefix} via ${remote_tfs_ip} ${vpp_ifnames[1]}
ip route del ${other_ip_prefix} via ${remote_tfs_ip} ${vpp_ifnames[1]}
ip route del ${local_trex_ip_prefix} via ${pktgen_ip}
EOF
            else
                cat >> $vppconfig << EOF
ipsec sa add 1${i} spi ${REMOTESPI} esp ${POLICY_CRYPTO_CONFIG} salt 0x1A2B tunnel-src ${remote_tfs_ip} tunnel-dst ${local_tfs_ip} use-esn use-anti-replay ${udp_encap_flag} inbound ${IN_IPTFS_CONFIG}
ipsec sa add 2${i} spi ${LOCALSPI} esp ${POLICY_CRYPTO_CONFIG} salt 0x1A2B tunnel-src ${local_tfs_ip} tunnel-dst ${remote_tfs_ip} use-esn use-anti-replay ${udp_encap_flag} ${IPTFS_CONFIG} ${extra_outbound_config}
EOF
            fi
            cat >> $vppconfig << EOF
ipsec policy $ADDDEL spd 1 priority 1000 outbound action bypass protocol 50 local-ip-range ${local_tfs_ip_range} remote-ip-range ${remote_tfs_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 outbound action protect sa 2${i} local-ip-range ${local_trex_ip_range} remote-ip-range ${remote_trex_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 outbound action protect sa 2${i} local-ip-range ${local_trex_ip_range} remote-ip-range ${other_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 outbound action protect sa 2${i} local-ip-range ${this_ip_range} remote-ip-range ${remote_trex_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 outbound action protect sa 2${i} local-ip-range ${this_ip_range} remote-ip-range ${other_ip_range}

ipsec policy $ADDDEL spd 1 priority 1000 inbound action bypass protocol 50 local-ip-range ${local_tfs_ip_range} remote-ip-range ${remote_tfs_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 inbound action protect sa 1${i} local-ip-range ${local_trex_ip_range} remote-ip-range ${remote_trex_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 inbound action protect sa 1${i} local-ip-range ${local_trex_ip_range} remote-ip-range ${other_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 inbound action protect sa 1${i} local-ip-range ${this_ip_range} remote-ip-range ${remote_trex_ip_range}
ipsec policy $ADDDEL spd 1 priority 100 inbound action protect sa 1${i} local-ip-range ${this_ip_range} remote-ip-range ${other_ip_range}
EOF
            if (( f_remove )); then
                cat >> $vppconfig << EOF
ipsec sa del 2${i}
ipsec sa del 1${i}
EOF
            else
                cat >> $vppconfig << EOF
ip route add ${local_trex_ip_prefix} via ${PKTGEN_IP}
ip route add ${other_ip_prefix} via ${remote_tfs_ip} ${vpp_ifnames[1]}
ip route add ${remote_trex_ip_prefix} via ${remote_tfs_ip} ${vpp_ifnames[1]}
EOF
            fi
        fi
        LAST=$((LAST + INC))
    done

    if (( f_use_policy )); then
        if (( f_remove )); then
            cat >> $vppconfig << EOF
set interface ipsec spd ${vpp_ifnames[1]} 1 del
ipsec spd del 1
EOF
        else
            echo "set interface ipsec spd ${vpp_ifnames[1]} 1" >> $vppconfig
        fi
    fi
fi

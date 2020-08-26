#!/usr/bin/env python
#
# Copyright (c) 2020, LabN Consulting, L.L.C
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import os
import sys

# virtualenv /path/to/vpp/venv
# source /path/to/vpp/venv activate.csh
# pip install aenum
# pip install cffi
# pip install ipaddress
# sudo env LD_LIBRARY_PATH=../../../build-root/install-vpp_debug-native/vpp/lib \
#   /path/to/vpp/venv/bin/python ./dump_etfs3_flows.py

INSTALL_PATH = os.path.realpath('../../../build-root/install-vpp_debug-native/vpp')
CLIENT_ID = "Vppclient"
VPP_JSON_DIR = INSTALL_PATH + '/share/vpp/api/core/'
PLUGIN_JSON_DIR = INSTALL_PATH + '/share/vpp/api/plugins/'
API_FILE_SUFFIX = '*.api.json'

sys.path.insert(0, INSTALL_PATH + '/lib/python2.7/site-packages')

import fnmatch
from vpp_papi import VPP

def load_json_api_files(json_dir=VPP_JSON_DIR, json_plugin_dir=PLUGIN_JSON_DIR, suffix=API_FILE_SUFFIX):
    jsonfiles = []
    for root, dirnames, filenames in os.walk(json_dir):
        for filename in fnmatch.filter(filenames, suffix):
            jsonfiles.append(os.path.join(json_dir, filename))

    for root, dirnames, filenames in os.walk(json_plugin_dir):
        for filename in fnmatch.filter(filenames, suffix):
            jsonfiles.append(os.path.join(json_plugin_dir, filename))

    if not jsonfiles:
        print('Error: no json api files found')
        exit(-1)

    return jsonfiles


def connect_vpp(jsonfiles):
    vpp = VPP(jsonfiles)
    r = vpp.connect("CLIENT_ID")
    print("VPP api opened with code: %s" % r)
    return vpp

def macaddr(s):
    return ':'.join(format(x, '02x') for x in bytearray(s))

def dump_etfs():
    print("Sending dump etfs3 encap")
    for flow in vpp.api.etfs3_encap_flow_dump(index=0xffff):
        print("\tencap index %u framesize %u rate %u aggr %uus rx %u tx %u %s %s" % \
              (flow.index, flow.framesize, flow.tx_rate_bits_msec, flow.max_aggr_time_usec, \
               flow.rx_sw_if_index, flow.tx_sw_if_index, macaddr(flow.stea), macaddr(flow.dtea)))
    for flow in vpp.api.etfs3_decap_flow_dump(index=0xffff):
        print("\tdecap index %u rx %u tx %u" % \
              (flow.index, flow.rx_sw_if_index, flow.tx_sw_if_index))

def dump_interfaces():
    print("Sending dump interfaces. Msg id: sw_interface_dump")
    for intf in vpp.api.sw_interface_dump():
        print("\tInterface, message id: sw_interface_details, interface index %u: %s" % \
              (intf.sw_if_index, intf.interface_name.decode()))


# Python apis need json definitions to interpret messages
vpp = connect_vpp(load_json_api_files())
dump_interfaces()
dump_etfs()

exit(vpp.disconnect())

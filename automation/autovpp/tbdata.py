# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# June 16 2020, Christian Hopps <chopps@labn.net>
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
import json
import os
from . import vpppath

tbdata = json.load(open(os.path.join(vpppath.g_vpp_srcdir, "automation/testbed_data.json")))
testbed_servers = tbdata["testbed_servers"]
testbed_trex = tbdata["testbed_trex"]
testbed_binonly = tbdata["testbed_binonly"]
testbed_docker = tbdata["testbed_docker"]
testbed_docker_physical = tbdata["testbed_docker_physical"]
testbed_interfaces = tbdata["testbed_interfaces"]

merge_path = "/etc/vpp-lab-data/testbed_data.json"
if os.path.exists(merge_path):
    merge_tbdata = json.load(open(merge_path))
    if "testbed_servers" in merge_tbdata:
        testbed_servers.update(merge_tbdata["testbed_servers"])
    if "testbed_trex" in merge_tbdata:
        testbed_trex.update(merge_tbdata["testbed_trex"])
    if "testbed_binonly" in merge_tbdata:
        testbed_binonly.extend(merge_tbdata["testbed_binonly"])
    if "testbed_docker" in merge_tbdata:
        testbed_docker.extend(merge_tbdata["testbed_docker"])
    if "testbed_interfaces" in merge_tbdata:
        testbed_interfaces.update(merge_tbdata["testbed_interfaces"])

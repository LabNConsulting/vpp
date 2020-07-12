# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# November 5 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
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

import socket
import re
from scapy.layers.inet import IP

import iptfs
from template_iptfs import BITRATE, MAXDELAY, MTU, PING_OVERHEAD, TemplateIPTFS4

IMixSpread = (x - PING_OVERHEAD for x in (40, 576, 40, 576, 40, 1500, 40, 576, 40, 40, 576, 40))


class TestIMixIPTFS(TemplateIPTFS4):
    """IPTFS IMix Tests"""

    MAXDELAY = 1000000
    tfs_config = re.sub("iptfs-max-delay-us [0-9]*", "iptfs-max-delay-us {}".format(MAXDELAY),
                        TemplateIPTFS4.tfs_config.decode('ascii')).encode('ascii')

    def imix_verify_tun_44(self, p, count=1, n_rx=None, clump=None):
        del n_rx

        self.vapi.cli("clear errors")

        # # Generate encrypted IPTFS stream (count packets)
        # tunpkts = iptfs.gen_encrypt_pktstream(p.scapy_tun_sa,
        #                                      self.tun_if,
        #                                      payload_size=payload_size,
        #                                      src=p.remote_tun_if_host,
        #                                      dst=self.pg1.remote_ip4,
        #                                      mtu=self.MTU,
        #                                      count=count)

        # self.verify_decap_44(p, tunpkts, seqnos=[i for i in range(count)])

        # Generate IP stream (count packets)
        ippkts = self.gen_pkts(self.pg1,
                               src=self.pg1.remote_ip4,
                               dst=p.remote_tun_if_host,
                               count=count,
                               payload_spread=IMixSpread)

        # Need this code if the entire stream *has* to fit in the queue
        size = 0
        for pkt in ippkts:
            size += len(pkt[IP])

        max_size = iptfs.get_max_queue_size(self.MAXDELAY, BITRATE, MTU, p.vpp_tun_sa)
        assert size <= max_size

        self.verify_encap_44(p, ippkts, clump)

    def test_tun_basic44_clump_all(self):
        self.imix_verify_tun_44(self.params[socket.AF_INET], count=1000)

    def test_tun_basic44_clump1(self):
        self.imix_verify_tun_44(self.params[socket.AF_INET], count=1000, clump=1)

    def test_tun_basic44_clump2(self):
        self.imix_verify_tun_44(self.params[socket.AF_INET], count=1000, clump=2)

    def test_tun_basic44_clump3(self):
        self.imix_verify_tun_44(self.params[socket.AF_INET], count=1000, clump=3)

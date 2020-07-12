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
from template_iptfs import TemplateIPTFS4


class TestFragIPTFS4(TemplateIPTFS4):
    """IPTFS Fragmentation Tests"""
    MTU = 256
    tfs_config = re.sub("iptfs-packet-size [0-9]*", "iptfs-packet-size 256",
                        TemplateIPTFS4.tfs_config.decode("ascii")).encode('ascii')

    def basic_verify_tun_44(self,
                            p,
                            count=1,
                            payload_size=230,
                            payload_spread=0,
                            n_rx=None,
                            clump=None):

        self.vapi.cli("clear errors")
        self.vapi.cli("clear iptfs counters")
        self.vapi.cli("clear interfaces")

        # # Generate encrypted IPTFS stream (count packets)
        # tunpkts = iptfs.gen_encrypt_pktstream(p.scapy_tun_sa,
        #                                      self.tun_if,
        #                                      payload_size=payload_size,
        #                                      src=p.remote_tun_if_host,
        #                                      dst=self.pg1.remote_ip4,
        #                                      mtu=self.MTU,
        #                                      count=count)

        # self.verify_decap_44(p, tunpkts, seqnos=[i for i in range(count)])
        # self.vapi.cli("iptfs debug enable packet")

        # Generate IP stream (count packets)
        ippkts = self.gen_pkts(self.pg1,
                               src=self.pg1.remote_ip4,
                               dst=p.remote_tun_if_host,
                               count=count,
                               payload_size=payload_size,
                               payload_spread=payload_spread)

        self.verify_encap_44(p, ippkts)

        # self.vapi.cli("iptfs debug disable packet")

    def test_tun_basic44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=1, payload_size=230)

    def test_tun_burst44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET],
                                 count=257,
                                 payload_size=150,
                                 payload_spread=100)

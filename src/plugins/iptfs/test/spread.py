# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# November 6 2019, Christian Hopps <chopps@labn.net>
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
from template_iptfs import MTU, TemplateIPTFS4
import iptfs

START=1400
STOP=1500

class TestSpread4(TemplateIPTFS4):
    """IPTFS Spread Tests"""
    def basic_verify_tun_44(self,
                            p,
                            count,
                            payload_size,
                            payload_spread,
                            clump=None):

        self.vapi.cli("clear errors")

        # # Generate encrypted IPTFS stream (count packets)
        # tunpkts = iptfs.gen_encrypt_pktstream(p.scapy_tun_sa,
        #                                       self.tun_if,
        #                                       payload_size=payload_size,
        #                                       src=p.remote_tun_if_host,
        #                                       dst=self.pg1.remote_ip4,
        #                                       mtu=MTU,
        #                                       count=count)

        # self.verify_decap_44(p, tunpkts, seqnos=[i for i in range(count)])

        # Generate IP stream (count packets)
        ippkts = self.gen_pkts(self.pg1,
                               src=self.pg1.remote_ip4,
                               dst=p.remote_tun_if_host,
                               count=count,
                               payload_size=payload_size,
                               payload_spread=payload_spread)

        self.verify_encap_44(p, ippkts, clump=clump)

        # self.vapi.cli("iptfs debug disable packet")

    def test_tun_basic44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET],
                                 count=(STOP-START+1),
                                 payload_size=START,
                                 payload_spread=STOP,
                                 clump=1)

    def test_tun_burst44_clump13(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET],
                                 count=(STOP-START+1) * 13,
                                 payload_size=START,
                                 payload_spread=STOP,
                                 clump=13)

    def test_tun_basic44_clump1(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET],
                                 count=(STOP-START+1),
                                 payload_size=START,
                                 payload_spread=STOP,
                                 clump=1)

    def test_tun_burst44_clump1(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET],
                                 count=(STOP-START+1) * 13,
                                 payload_size=START,
                                 payload_spread=STOP,
                                 clump=1)

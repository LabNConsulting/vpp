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
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes

import socket
from template_iptfs import MTU, TemplateIPTFS4
import iptfs


class TestBasicIPTFS4(TemplateIPTFS4):
    """IPTFS Basic Tests"""
    def verify_tun_44(self, p, ippkts, tunpkts, clump=None):
        "Verify ippkts are encrypted/encapsulated, and that tunpkts are decrypted correctly.."

        # ex1 = None
        # e_recv_pkts = []
        if ippkts:
            ex1, e_recv_pkts, tx_pkts = self._verify_encap_44_noex(p, ippkts)  # pylint: disable=W0612

        # self.logger.info("XXXT1")
        # self.logger.info(self.vapi.ppcli("show trace"))
        # self.logger.info("XXX: VPP enc pkt: {}\nScappy tun pkt: {}\n".format(
        #     e_recv_pkts[0].show(dump=True), tx_pkts[0].show(dump=True)))

        # ex2 = None
        # self.vapi.ppcli("iptfs debug enable packet")

        if tunpkts:
            ex2, rippkts, e_sent_pkts = self._verify_decap_44_noex(  # pylint: disable=W0612
                p,
                tunpkts,
                seqnos=[x for x in range(len(ippkts))],
                clump=clump)

        # self.vapi.ppcli("iptfs debug disable packet")

        # Do some comparison here to failed packets.
        if ex1 or ex2:
            self.logger.info("XXX: VPP enc pkt: {}:{}\nScappy tun pkt: {}:{}\n".format(
                len(e_recv_pkts), e_recv_pkts[0].show(dump=True) if e_recv_pkts else "[Empty]",
                len(tunpkts), tunpkts[0].show(dump=True)))

        # self.logger.info("XXXT2")
        # self.logger.info(self.vapi.ppcli("show trace"))
        # self.logger.info(
        #     "XXX: sent ip pkt: {}\n recv enc pkt: {}\nsent enc pkt: {}\nrecv ip pkt: {}\n".format(
        #         ippkts[0].show(dump=True) if ippkts else "None",
        #         e_recv_pkts[0].show(dump=True),
        #         e_sent_pkts[0].show(dump=True),
        #         rippkts[0].show(dump=True) if rippkts else "None"))

        self.logger.info(self.vapi.ppcli("show error"))
        self.logger.info(self.vapi.ppcli("show ipsec all"))

        if ex1:
            raise ex1  # pylint: disable=E0702
        if ex2:
            raise ex2  # pylint: disable=E0702

        # Verify the scapy generated ESP packet is the same size as the IPTFS one,
        # this is really to catch scapy bug.
        if len(tunpkts[0]) != len(e_recv_pkts[0]):
            print(len(tunpkts[0]), len(e_recv_pkts[0]))
            self.logger.info("XXX: VPP enc pkt: {}\nScappy tun pkt: {}\n".format(
                e_recv_pkts[0].show(dump=True), tunpkts[0].show(dump=True)))
        assert len(tunpkts[0]) == len(e_recv_pkts[0])

        # self.verify_counters(p, len(tunpkts))

    # def setup_params(self):
    #     # Skip config that set GCM. This is geting ugly.
    #     TemplateIpsec.setup_params(self)

    def basic_verify_tun_44(self, p, count=1, payload_size=56, n_rx=None, clump=None):
        self.vapi.cli("clear errors")

        # Generate encrypted IPTFS stream (count packets)
        tunpkts = iptfs.gen_encrypt_pktstream(p.scapy_tun_sa,
                                              self.tun_if,
                                              src=p.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              mtu=MTU,
                                              count=count,
                                              payload_size=payload_size)
        # for i, pkt in enumerate(tunpkts):
        #     self.logger.critical("tunpkt %d: %s", i, pkt.show(dump=True))

        # Generate IP stream (count packets)
        ippkts = self.gen_pkts(self.pg1,
                               src=self.pg1.remote_ip4,
                               dst=p.remote_tun_if_host,
                               count=count,
                               payload_size=payload_size)

        self.verify_tun_44(p, ippkts, tunpkts, clump=clump)

    def test_tun_basic44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=1)

    def test_tun_burst44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=256)

    def test_tun_small_packet_burst44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=100, payload_size=1)


__author__ = 'Christian Hopps'
__date__ = 'November 5 2019'
__version__ = '1.0'
__docformat__ = "restructuredtext en"

# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# November 3 2019, Christian Hopps <chopps@labn.net>
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
import unittest
from framework import VppTestRunner

# from basic import TestBasicIPTFS4
# TestBasicIPTFS4.dpdk_crypto_dev = "vdev crypto_aesni_gcm vdev crypto_null"

# from dontfrag import TestBasicDontFragmentIPTFS4, TestBasicDontFragmentChainedIPTFS4
# TestBasicDontFragmentIPTFS4.dpdk_crypto_dev = "vdev crypto_aesni_gcm vdev crypto_null"
# TestBasicDontFragmentChainedIPTFS4.dpdk_crypto_dev = "vdev crypto_aesni_gcm vdev crypto_null"

# Not enabled yet
# from frag import TestFragIPTFS4
# from imix import TestIMixIPTFS
# from reorder import *

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)

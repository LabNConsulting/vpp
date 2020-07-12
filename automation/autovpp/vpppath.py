# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 8 2020, Christian E. Hopps <chopps@labn.net>
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
"""
A module for extracting VPP paths based on this modules location.
"""
import glob
import os
import re
import sys

#
# Get the main directory paths
#
__dir_path__ = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
g_vpp_srcdir = os.path.dirname(__dir_path__)
g_def_logsdir = f"/tmp/autovpp-{os.environ['USER']}"
g_trex_lib_dir = os.path.join(g_vpp_srcdir, "automation/docker-trex-extract")

if "VPP_CROSS_INSTALL_ROOT" in os.environ:
    _install_root = os.environ["VPP_CROSS_INSTALL_ROOT"]
    if not os.path.exists(_install_root):
        _vpp_tag = "debug"
        _vpp_tag = "armv8-a+crc"
        #print(f"envvar VPP_CROSS_INSTALL_ROOT set but does not exist: {_install_root}")
        #sys.exit(1)
    else:
        m = re.match("install-([a-zA-Z0-9_]+)-([a-z0-9_]+)", os.path.basename(_install_root))
        if not m:
            print(
                f"Cant parse envvar VPP_CROSS_INSTALL_ROOT last directory into components (tag and arch): {_install_root}"
            )
            sys.exit(1)
        _vpp_tag = m.group(1)
        _vpp_arch = m.group(2)

    # We can't really do much about this, it's not built for native but for the arch.
    g_vpp_native_root = None
    g_vpp_ldpath = None

    # We don't use this anymore so just set to 19 for now.
    g_vpp_maj_version = 20
else:
    if os.path.exists(os.path.join(g_vpp_srcdir, "build-root/install-vpp-native/vpp/bin/vpp")):
        _vpp_tag = "vpp"
        _vpp_arch = "native"
    elif os.path.exists(
            os.path.join(g_vpp_srcdir, "build-root/install-vpp_debug-native/vpp/bin/vpp")):
        _vpp_tag = "vpp_debug"
        _vpp_arch = "native"
    else:
        print("Can't find VPP binary, perhaps make build/build-release?", file=sys.stderr)
        sys.exit(1)

    g_vpp_native_root = os.path.join(g_vpp_srcdir, f"build-root/install-{_vpp_tag}-{_vpp_arch}/vpp")
    # Need to add lib directories to LD_LIBRARY_PATH
    _ext_root = os.path.join(g_vpp_srcdir, f"build-root/install-{_vpp_tag}-{_vpp_arch}/external")
    g_vpp_ldpath = f":{g_vpp_native_root}/lib:{_ext_root}/lib"
    if "LD_LIBRARY_PATH" in os.environ:
        os.environ["LD_LIBRARY_PATH"] += f":{g_vpp_ldpath}"
    else:
        os.environ["LD_LIBRARY_PATH"] = g_vpp_ldpath

    gm = glob.glob(os.path.join(g_vpp_native_root, "lib/libvatplugin.so.*"))
    m = re.match(r".*libvatplugin.so.(\d+)\..*", gm[0])
    g_vpp_maj_version = int(m.group(1))

g_g2 = os.path.join(g_vpp_srcdir, f"build-root/build-vpp-native/vpp", f"bin/g2")
if not os.path.exists(g_g2):
    g_g2 = os.path.join(g_vpp_srcdir, f"build-root/build-vpp_debug-native/vpp", f"bin/g2")
    if not os.path.exists(g_g2):
        g_g2 = None

g_c2cpel = os.path.join(g_vpp_srcdir, f"build-root/build-vpp-native/vpp", f"bin/c2cpel")
if not os.path.exists(g_c2cpel):
    g_c2cpel = os.path.join(g_vpp_srcdir, f"build-root/build-vpp_debug-native/vpp", f"bin/c2cpel")
    if not os.path.exists(g_c2cpel):
        g_c2cpel = None

# __sitepkg__ = glob.glob(os.path.join(g_vpp_root, "lib*/python*/site-packages"))
# if os.path.exists(__sitepkg__[0]):
#     print(f"Found: {__sitepkg__[0]}")
#     sys.path.append(__sitepkg__[0])
# else:
#     print("Can't find VPP python packages, perhaps make build/build-release?", file=sys.stderr)
#     sys.exit(1)
_papi_dir = os.path.join(g_vpp_srcdir, "src/vpp-api/python")
assert os.path.exists(_papi_dir)
sys.path.append(_papi_dir)

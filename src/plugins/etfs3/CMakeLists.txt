#
# Copyright (c) 2020, LabN Consulting, L.L.C.
# Copyright (c) 2015 Cisco and/or its affiliates.
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

add_vpp_plugin(etfs3

    SOURCES
    etfs3.c
    etfs_api.c
    etfs_buffer.c
    etfs_decap.c
    etfs_encap.c
    etfs_format.c
    etfs_fragment.c
    etfs_output.c
    etfs_pacer.c
    etfs_thread.c
    etfs_zpool.c

    API_FILES
    etfs3.api

    API_TEST_SOURCES
    etfs3_test.c

    INSTALL_HEADERS
    etfs3.h
    etfs3_all_api_h.h
    etfs3_msg_enum.h
    etfs_buffer.h
    etfs_thread.h
    etfs_zpool.h
)

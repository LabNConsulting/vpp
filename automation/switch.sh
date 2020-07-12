#!/usr/bin/expect -f
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

# exp_internal 1
set prompt0 "Switch3-red>"
set prompt1 "Switch3-red#"

# device
set modem /dev/serial/by-name/turboiron

# # keep it open
# exec sh -c "sleep 3 < $modem" &
# # serial port parameters
# exec stty -F $modem 9600 raw -clocal -echo -istrip -hup

# connect
send_user "connecting to $modem\n"
set port [open $modem {RDWR NOCTTY}]
fconfigure $port -mode 9600,n,8,1
# fconfigure $port -mode 115200,n,8,1
fconfigure $port -blocking 0 -buffering none

send_user "spawning on  $port \n"
spawn -open $port

send_user "exit with ~.\n"

interact {
    ~. exit
    ~~ {send "\034"}
}

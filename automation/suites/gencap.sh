#!/bin/bash
#
# May 5 2020, Christian E. Hopps <chopps@labn.net>
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
#
set -x

logdir="$HOME/logs/gencap-$(date +%Y%m%d)"

# Overwriting for now

rm -rf $logdir
mkdir -p $logdir

rate=10M
latency=100K
duration=10
percentage=50
testbed=B
            # --event-log-size=2M \
cargs=" --logdir=$logdir \
        --testbed=$testbed \
        --max-latency $latency \
        --rate=$rate \
        --duration=$duration \
        --capture=ens2f1 \
        --null \
        --percentage=$percentage"


~/w/vpp/automation/runtests.py -v $cargs test_imix_iptfs.py

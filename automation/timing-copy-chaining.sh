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
export VPPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
source $VPPDIR/automation/setup.sh

TESTBED=${1}; shift
if [[ -z "$TESTBED" ]]; then
    echo "Specify testbed to run timing test on"
    exit 1
fi

outdir=$1; shift
if [[ -z $outdir ]]; then
    echo "Specify run log save directory"
    exit 1
fi
if [[ -d $outdir ]]; then
    echo "$outdir already exists"
    exit 1
fi
mkdir -p $outdir

source $VPPDIR/automation/timing-setup.sh

rate=100M

# Do large impulse testing
for ups in 64 1500; do
    for durimp in 4 30; do
        for mode in copy chaining; do
            ./runtests.py -U $ups --$mode -d $durimp -r $rate --impulses=$durimp -p 100 -v -C ${user_capture_intf},${tfs_capture_intf} -T "${TESTBED}" --log-replace --logdir /tmp/timing test_verify_timing.py
            outbase=impulse-$durimp-$ups-$rate-${durimp}s-$mode
            outname=$outdir/$outbase
            mv /tmp/timing $outname
            (cd $outname &&
                 $VPPDIR/automation/plot2.py --output=${outbase}.pdf \
                                             TFS-1500-$rate-${mode}  ${tfs_capture_fname} \
                                             "USER-${ups}-impulse-${durimp}"' (offset-from-above)' ${user_capture_fname}
             )
        done
    done
done

# Do small impulse testing
ups=64
for imp in 18,200; do
    for mode in copy chaining; do
        ./runtests.py -U ${ups} --${mode} -d .1 -r ${rate} --impulses=${imp} -p 100 -v -C ${user_capture_intf},${tfs_capture_intf} -T "${TESTBED}" --log-replace --logdir /tmp/timing test_verify_timing.py
        impname=$(echo $imp | tr , -)
        outbase=impulse-$impname-$ups-$rate-$mode
        outname=$outdir/$outbase
        mv /tmp/timing $outname
        (cd $outname &&
             $VPPDIR/automation/plot2.py --xmax=.2 --output=${outbase}.pdf \
                                         TFS-1500-$rate-${mode}  ${tfs_capture_fname} \
                                         "USER-${ups}-impulse-${imp}"' (offset-from-above)' ${user_capture_fname}
        )
    done
done

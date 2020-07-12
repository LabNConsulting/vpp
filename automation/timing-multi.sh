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

rate=50M
connections=4
nrxq=2
stdargs="--connections=${connections} --rx-queues=${nrxq} -r $rate -p 100 -v -C ${user_capture_intf},${tfs_capture_intf} -T ${TESTBED} --log-replace --logdir /tmp/timing test_verify_timing.py"

# Do large impulse testing
for ups in 64 1500; do
    for durimp in 4 30; do
            ./runtests.py -U $ups -d 1 -r $rate --impulses=$durimp $stdargs
            outbase=impulse-$durimp-$ups-$rate-${durimp}s
            outname=$outdir/$outbase
            mv /tmp/timing $outname
            set -x
            (cd $outname &&
                 $VPPDIR/automation/plot-multi.py --output=${outbase}.pdf \
                            TFS-1500-x${connections}-${rate} ${tfs_capture_fname} \
                            "USER-x${connections}-${ups}-impulse-${durimp}"' (offset-from-above)' ${user_capture_fname}
             )
            set +x
    done
done

exit 0

# Do small impulse testing
ups=64
for imp in 18,200; do
        ./runtests.py ${ups} -d .1 --impulses=${imp} $stdargs
        impname=$(echo $imp | tr , -)
        outbase=impulse-$impname-$ups-$rate
        outname=$outdir/$outbase
        mv /tmp/timing $outname
        (cd $outname &&
             $VPPDIR/automation/plot-multi.py --xmax=.2 --output=${outbase}.pdf \
                                         TFS-1500-$rate ${tfs_capture_fname} \
                                         "USER-${ups}-impulse-${imp}"' (offset-from-above)' ${user_capture_fname}
        )
done

#!/bin/bash
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
export AUTODIR=$VPPDIR/automation
autovpp=$VPPDIR/automation/autovpp

CID=""

handler () {
    if [[ $CID ]]; then
        docker stop $CID
        docker rm $CID
    fi
}

trap handler EXIT

if [[ $1 ]]; then
    extract_dir=$1
    SUDO=
else
    extract_dir=$AUTODIR/docker-trex-extract
fi

# else
#     extract_dir=/opt/trex
#     SUDO=sudo
# fi


trex_image=$(sed -e '/image:.*trex.*/!d;s/.*image: *//' $AUTODIR/docker-compose.yml.tpl)
trex_version=${trex_image#labn/trex:}
tdir=$extract_dir/$trex_version
libdir=$tdir/automation/trex_control_plane/interactive

symlink1=$AUTODIR/trex_stl_lib
symlink2=$AUTODIR/trex

for symdir in trex trex_stl_lib; do
    symlink=$AUTOVPP/$symdir
    if [[ -h $symlink ]]; then
        if [[ "$(realpath $symlink)" == "$(realpath $libdir/$symdir)" ]]; then
            exit 0
        fi
        echo "Symlink to wrong version will extract and update"
    elif [[ -e $symlink ]]; then
        echo "$symlink not a symlink"
        exit 1
    fi
done

if [[ ! -e $tdir ]]; then
    CID=$(docker create ${trex_image})
    $SUDO mkdir -p $extract_dir
    $SUDO docker cp $CID:/trex $tdir
else
    echo "$tdir already exists"
fi

echo "== Creating/Updating symlinks to trex libraries"
# $SUDO ln -fs $libdir/trex $autovpp/
for symdir in trex trex_stl_lib; do
    symlink=$AUTODIR/$symdir
    set -x
    ln -fs $libdir/$symdir $symlink
    set +x
done

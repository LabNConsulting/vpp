#!/bin/bash
#
# October 7 2020, Christian Hopps <chopps@labn.net>
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
VPPDIR=${VPPDIR:="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"}

if [[ ! -f $VPPDIR/automation/testbed_data.json ]]; then
    echo "Can't find $VPPDIR/automation/testbed_data.json"
    exit 1
fi

_jq () {
    if [[ -e "/etc/vpp-lab-data/testbed_data.json" ]]; then
        jq -s '.[0] * .[1]'  /etc/vpp-lab-data/testbed_data.json $VPPDIR/automation/testbed_data.json
    else
        jq -s '.[0]' < $VPPDIR/automation/testbed_data.json
    fi
}

TBARRAYS=($(_jq | jq -r '. | to_entries | .[].key'))
for arr in ${TBARRAYS[@]}; do
    declare item_name=$arr
    declare item_type="$(_jq | jq -r ".${arr}"'| type')"

    case $item_type in
    object)
        # echo "Got object in $arr"
        declare -A $arr
        # Associative array
        item_type="$(_jq | jq -r ".$arr | .[] | type" | head -1)"
        if [[ "$item_type" == "array" ]]; then
            # entries contain lists
            eval $(_jq | jq -r ".$item_name"' | to_entries | .[] | "'"$arr"'[" + .key + "]=\"" + ( .value | join(" ") )+ "\""')
        elif [[ "$item_type" == "object" ]]; then
            # entries contain dictionaries of items or lists of items
            declare subkeys=$(_jq | jq -r ".$item_name"' | keys | .[]')
            for subkey in $subkeys; do
                declare sub_item_type="$(_jq | jq -r ".$arr"'["'"$subkey"'"] | .[] | type' | head -1)"
                if [[ "$sub_item_type" == "array" ]]; then
                    eval $(_jq | jq -r ".$item_name"'["'"$subkey"'"] | to_entries | .[] | "'"$arr"'['"$subkey"'," + .key + "]=\"" + ( .value | join(" ") ) + "\""')
                else
                    eval $(_jq | jq -r ".$item_name"'["'"$subkey"'"] | to_entries | .[] | "'"$arr"'['"$subkey"'," + .key + "]=\"" + .value + "\""')
                fi
            done
        else
            # entries contain values
            eval $(_jq | jq  -r ".$arr"' | to_entries | .[] | "'"$arr"'[" + (.key|tostring) + "]=\"" + .value + "\""')
        fi
        ;;
    array)
        # echo "Got array in $arr"
        declare arrvalues=$(_jq | jq ".${arr}"' | .[] ' | xargs)
        eval "declare -a $arr=($arrvalues)"
        ;;
    esac
done

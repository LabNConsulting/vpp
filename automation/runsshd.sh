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

#
# The purpose of this script is to run sshd in a way that it will exit
# when the invoker goes away (i.e., SIGHUP). Normally sshd ignores SIGHUP.
# 



# define "debuglog" to turn on debugging
# debuglog=/tmp/runsshd-debug


debug() {
    if [[ -z "${debuglog}" ]]; then
	return
    fi
    if [[ -z "${_did_first_debug}" ]]; then
	_did_first_debug=1
	echo $* > ${debuglog}
    else
	echo $* >> ${debuglog}
    fi
}

#
# Assume sshd has the same pgid as its parent sudo
#
find_sshd_pgid() {
    local childpid=$1

    ps -o pgid ${childpid} | sed -e '1d' -e 's/ //g'
}

#
# sudo does not reliably relay signals to its child process
# so we must try to signal the whole process group
#
cleanup() {
    local SIG
    SIG="QUIT"
    debug "cleanup, selfpid is [$$], PID is [${PID}]"
    if [[ -n "${PID}" ]]; then
	debug "cleanup signaling pid ${PID} with ${SIG}"
	sudo kill -${SIG} ${PID}
	debug "kill exited with $?"
    fi
    if [[ -n "${PGID}" ]]; then
	#
	# The following might also signal this running script (goodbye!)
	#
	debug "cleanup signaling pgid ${PGID} with ${SIG}"
	sudo kill -${SIG} -${PGID}
	debug "kill exited with $?"
    fi
    debug "cleanup exiting"
    exit 1
}

trap cleanup HUP

listenip=""
listenport=""

debug "start" >${debuglog}


usage () {
    cat << EOF
$0: -i listenip -p listenport"

    -i listenip :: IP address sshd should listen on
    -p listenport :: port number sshd should listen on
EOF
    debug "usage"
    exit 1
}

while getopts hi:p: opt; do
    case $opt in
        i)
            listenip="$OPTARG"
            ;;
        p)
            listenport="$OPTARG"
            ;;
        h)
            usage
            ;;
    esac
done

if [[ ( -z "${listenip}" ) || ( -z "${listenport}" ) ]]; then
    usage
fi

sudo /usr/sbin/sshd -D -o ListenAddress=${listenip}:${listenport} &

PID=$!
PGID=`find_sshd_pgid ${PID}`

debug "background sshd has pid ${PID}, pgid ${PGID}"

# wait enables us to receive HUP
wait $PID


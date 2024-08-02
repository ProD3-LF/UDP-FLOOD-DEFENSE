#!/bin/bash

#/* SPDX-License-Identifier: Apache-2.0 */
#/* Copyright (c) 2012-2024 Applied Communication Sciences
# * (now Peraton Labs Inc.)
# *
# * This software was developed in work supported by the following U.S.
# * Government contracts:
# *
# * HR0011-20-C-0160 HR0011-16-C-0061
# *
# *
# * Any opinions, findings and conclusions or recommendations expressed in
# * this material are those of the author(s) and do not necessarily reflect
# * the views, either expressed or implied, of the U.S. Government.
# *
# * DoD Distribution Statement A
# * Approved for Public Release, Distribution Unlimited
# *
# * DISTAR 40011, cleared July 24, 2024
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# * http://www.apache.org/licenses/LICENSE-2.0
# */

TOP_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color
SCRIPT_NAME=$(basename $0)
green () { echo -e "$SCRIPT_NAME: $GREEN${*}$NC"; }
red ()   { echo -e "$SCRIPT_NAME: $RED${*}$NC"; }
get_config() {
    rc=$(egrep "^$1:" $TOP_DIR/common/config|cut -d':' -f 2|sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
    echo ${rc:-$2}
}

cd $TOP_DIR
mkdir -p log

echo Restarting the topology
cd $TOP_DIR/network
export DIST=$TOP_DIR
docker compose down
docker compose up -d

docker exec -d src-mec bash -c "cd /DIST/remediator; python3 iptables_ctl.py 1> /DIST/log/iptables_ctl.log 2>&1"
docker exec tgt-mec mkfifo  $(get_config icmp_sensor_fifo /tmp/icmpSensorFifo)
docker exec -d tgt-mec bash -c "cd /DIST/sensor; ./tcpdumpSensor 1>/DIST/log/tcpdumpSensor-stdout.log 2>/DIST/log/tcpdumpSensor-stderr.log"
docker exec -d tgt-mec bash -c "cd /DIST/detector; ./icmp_detector 1>/DIST/log/icmp_detector_command-stdout.log 2>/DIST/log/icmp_detector_command-stderr.log"

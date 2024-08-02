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

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Set up apt
RUN apt-get -qy update && apt-get upgrade -y && apt-get install -qy \
    build-essential \
    iputils-ping \
    tcpdump \
    iperf \
    iproute2 \
    iptables \
    python3 \
    python3-pip

RUN python3 -m pip install netifaces

# Below fixes the error: 'tcpdump: Couldn't change ownership of savefile'
RUN ["/bin/bash", "-c", "if [[ -e /usr/sbin/tcpdump ]] ; then test /usr/sbin/tcpdump -ef /usr/bin/tcpdump; ret=$? ; if [[ $ret -eq 0 ]] ; then echo 'No need to mv tcpdump' ; else mv /usr/sbin/tcpdump /usr/bin/tcpdump ; fi ; fi"]

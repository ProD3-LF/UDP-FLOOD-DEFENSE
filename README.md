## Introduction

Continuous volumetric (CV) attacks, examples of which include `Mirai UDP` and `UDP-Plain` attacks [(See IoT Attack Handbook)](https://www.radware.com/getattachment/402db7f3-0467-4fa3-bb9a-ae88b728e91b/MiraiHandbookEbookFinal_04.pdf.aspx), involve each bot generating a UDP flow with a randomized pair of source and destination port numbers.  This repository contains a software component, called [ICMP Detector](detector/README.md), that can be used to detect a CV attack in real time and help mitigate the attack by generating alert messages towards access networks from which attack packets originate [(see expected network topology)](network/README.md).  Developed for **ProD3** (Programmble Defenses in Depth), a project building defenses for a variety of volumetric attacks for the DARPA Open, Programmable, Secure 5G program (**OPS-5G**) program, `ICMP Detector` works by sensing an abnormal level of `ICMP Port Unreachable` packets from protected hosts.

In addition to `ICMP Detector`, this repository also includes:
- [Example network-in-a-box](network/README.md) to illustrate network architecture and connctions requirements for `ICMP Detector`
- [Iptables Controller](remediator/README.md) to illustrate the use of alerts from `ICMP Detector` to mitigate attack packets 

The network in a box is provided as a sandbox for users to get insights into the end-to-end operation of the detection and defense mechanisms built as part of the ProD3 solution suite.  Meanwhile, `ICMP Detector` can be deployed in users' networks as they see fit, and `Iptables Controller` can be used as the basis for designing and implementing a high performant mitigation mechanism.

## Environment

The software in this repository is created and tested on a Linux machine running `Ubuntu 22.04.4 LTS` with [docker engine](https://docs.docker.com/engine/install/ubuntu/) installed.  In the below, **`TOP_DIR`** refers to the top directory of this repository.  It is assumed that the Linux commands below are issued at the command line in a terminal window.

## Usage

To use the components and tools in this repository, perform the following steps: 

1. Build a docker image tagged `vanilla/base`, e.g.:
    1. `cd TOP_DIR/network`
    2. `docker build . -t vanilla/base`
2. Build `ICMP Detector`
    1. `cd TOP_DIR`
    2. `make`
3. Stand up example network and start `ICMP Detector` and `IPtables Controller`
    1. `cd TOP_DIR`
    2. `./run.sh`
    - `run.sh` performs all the necessary steps to start `IPtables Controller` on the `src-mec` container and `ICMP Detector` on the `tgt-mec` container
    - In each container, the user's `$HOME` is mapped to `/DIST` so that the user has access to the files and tools on the user's host.  This is especially useful when using the user's own tool to lauch CV attacks inside the `attacker` container.  See [Launch Attack](#launch_attack) for suggestions
    - The `run.sh` script creates a `TOP_DIR/log` directory where the log entries from the various components are gathered in their respective log files
4. <a name="launch_attack">Launch Attack</a>
    - This repository does not include software used to launch continous volumetric attacks
    - The user can download and build [Mirai](https://github.com/jgamblin/Mirai-Source-Code) and use it to launch its UDP attak towards `192.168.2.1` in the `attacker` container 
5. Validate that the CV attack has been mitigated:
    1. Make sure the `whitelist` filtering rules are in place at `src-mec`, e.g., `docker exec -it src-mec iptables -L` or see `TOP_DIR/log/iptables_ctl.log`
        - See [ICMP Detector](detector/README.md) for information on detector and whitelist configurations
    2. Run `tcpdump` at `target` to make sure that only whitelisted packets are being received
        1. `cd TOP_DIR`
        2. `./run_tcpdump.sh`
6. Stop example network and software components
    1. `cd TOP_DIR`
    2. `./stop.sh`
    - NOTE: `TOP_DIR/run.sh` also stops the previous instances of the network and software components

***

Copyright (c) 2024 Peraton Labs Inc.

DoD Distribution Statement A: Approved for Public Release, Distribution Unlimited.

DISTAR 40011, cleared July 24, 2024

This software was developed in work supported by U.S. Government contracts HR0011-15-C-0098 and HR0011-20-C-0160.

Any opinions, findings and conclusions or recommendations expressed in
this material are those of the author(s) and do not necessarily
reflect the views, either expressed or implied, of the
U.S. Government.

All files are released under the Apache 2.0 license unless specifically noted otherwise

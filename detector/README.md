## Design and Implementation Overview

The ICMP Detector (icmp_detector) reads the output from a sensor, i.e., `Tcpdump Sensor`, and sends alert messages through the control plane to instruct downstream remediation modules, like `Iptables Controller`, to take action, as illustrated in the diagram below.

![sensor and detector](artifacts/sensor_and_detector.png)

The general flow of the attack and the defense mechanism is as follows:

1. A UDP flood attack begins, and the attack packets travel from the Source MEC to the Target MEC and then to the target.
1. The target responds with ICMP port unreachable messages, which are detected by the sensor running on the Target MEC.
1. The sensor detects these messages, parses them, generates data about packets causing “ICMP Port Unreachable” messages, and sends this data to a Linux FIFO file. Each entry in the FIFO is in the format “IP:port", representing the IP address and the port being attacked.
1. The ICMP Detector reads the data entries from the FIFO and sends remediation directives via the control plane to the remediation module.

When the UDP attack initiates, the ICMP Detector collects the attacked individual ports into port ranges and sends these ranges to the remediation module for blocking. Unfortunately, the remediation module may have a limitation on the number of rules it can apply within a short period of time.  To prevent overwhelming the remediation module, the ICMP Detector periodically sends updated port ranges, which is configurable through the `ports_attacked_threshold` parameter. `ports_attacked_threshold` represents the number of ports that have been attacked and not reported yet to the remediation module. If the remediation module can quickly apply the blocking rules, reduce `ports_attacked_threshold`. Conversely, increase `ports_attacked_threshold` to lessen the load on the remediation module.

If the attack intensity exceeds configurable thresholds (`new_port_count_threshold` or `packets_per_interval_threshold`), the ICMP Detector will send `whitelist` remediation messages to the remediation module.  With a whitelist message, the remediation module will block all ports, except those on the request, preventing most attack traffic from reaching the core network.

The behavior of `icmp_detector` is configurable through various parameters described below.

## Configuration Details
The configuration data in `common/config` file governs the ICMP detector behavior. It contains lines in the following format:

    parameter: value

The list of valid parameters is descrined below:

<details open><summary>use_whitelist</summary>
Optional. Values 0 or 1. Default value 0. When set to 1, the whitelist remediation is enabled. When this parameter is set to 0 or missing, `ICMP Detector` would only send `blacklist` messages.  A blacklist message explicitly specifies an IP address and port range to block.
</details>

<details open><summary>new_port_count_threshold</summary>
Optional. Integer. Default value -1. When set to a positive integer number, the whitelist remediation request is sent when the number of unique ports under attack exceeds `new_port_count_threshold` during the `look_back_time` interval.
</details>

<details open><summary>packets_per_interval_threshold</summary>
Optional. Integer. Default value -1. When set to a positive integer number, the whitelist remediation request is sent when the number of ICMP packets received by the detector exceeds `packets_per_interval_threshold` during the `look_back_time` interval.
</details>

<details open><summary>look_back_time</summary>
Optional. Integer. Default value 10000000. Time interval in `microseconds` to look back when deciding if a whitelist request should be sent. Used together with `new_port_count_threshold` and `packets_per_interval_threshold`.
</details>

<details open><summary>ports_attacked_threshold</summary>
Optional. Integer greater than or equal to 0. Default value 0. Number of unique ports under attack to collect before sending a blacklist remediation request message.
</details>

<details open><summary>max_hold_time</summary>
Optional. Positive integer. Default value 100.  Maximum wait time in `microseconds` since the first blacklist remediation request message until a new blacklist request message is sent for newly detected ports.
</details>

<details open><summary>max_ranges_per_message</summary>
Optional. Positive integer. Default value 2048. Maximum number of port ranges per blacklist remediation request message. A port range greater than the specified value is broken up into `max_ranges_per_message` ranges per message.  Note that this parameter is internal to the ProD3's implementation of a control plane, and strictly speaking, it is needed for the `ICMP Detector` included in this repository.  It is recommended that the user does not change this parameter.

</details>

<details open><summary>icmp_sensor_fifo</summary>
Optional. The name of the FIFO file to be written by `tcpdump sensor` and read by `ICMP Detector` The default name is `/tmp/icmpSensorFifo`
</details>

<details open><summary>icmp_detector_log_file</summary>
Optional. Main log file name. Default is `/tmp/icmp_detector.log`
</details>

<details open><summary>icmp_detector_ssv_file</summary>
Optional. Log file with abbreviated log data. Default is /tmp/icmp_detector.ssv
</details>

<details open><summary>remediation_ip</summary>
Optional. IP address of the remediation module server, i.g., `src-mec` in the example network. Default is 172.20.30.11.
</details>

<details open><summary>remediation_port_blacklist</summary>
Optional. Port number where the remediation module listens for blacklist remediation requests. Default: 4444.
</details>

<details open><summary>remediation_port_whitelist</summary>
Optional. Port number where the remediation module listens for whitelist remediation requests. Default: 4446.
</details>

##### Behavior with `use_witelist` Set to 0
When UDP attack starts, `ICMP Detector` starts receiving `ICMP Port Unreachable` messages.  It extracts ports from these messages and consolidates them into port ranges. When `ports_attacked_threshold` ports are collected, `ICMP Detector` sends all collected port rangesin a blacklist remediation request message. When the number of changed port ranges exceeds `max_ranges_per_message`, `ICMP Detector` breaks all the port ranges into the configured or smaller ranges and sends each range in its own blacklist message. After the first blacklist request message, `ICMP Detector` continues to collect new ports as reported in `ICMP Port Unreachable` messages and consolidate them into ranges, and would send the delta every `max_hold_time` microseconds.

##### Behavior with `use_witelist` Set to 1
`ICMP Detector` initially behaves in the same way as as with `use_witelist` set to 0 (as described above). However, when the attack gets too intense, i.e., `new_port_count_threshold` or `packets_per_interval_threshold` is exceeded during the `look_back_time` time interval, `ICMP Detector` sends a whitelist remediation request message, after which no additional remediation messages are sent.

##### About Whitelist
A whitelist remediation message defines a protected service on the target machine by specifying the ports it uses to listen on. The whitelist includes the list of utilized ports (or port ranges) that must not be blocked, as specified in the configuration file. The whitelist is defined in the same configuration file as the previously described configuration parameters, and has the following format:

    IP: Port_from,Port_to,protocol

For example:

    192.168.2.1: 6000,6001,17

The above means that port 6000 UDP (17) on 192.168.2.1 is utilized (and should be whitelisted). The ranges are specified as [Port_from, Port_to), i.e., the lower end of the range is included and the higher end of the range is not.

The valid values for the protocol are:

    17 - UDP
    6  - TCP

##### Configuration Example

To better illustrate the paramters described above, consider the example configuration below:

    ports_attacked_threshold: 50
    max_hold_time: 100000
    max_ranges_per_message: 2048
    use_whitelist: 1
    packets_per_interval_threshold: 200
    new_port_count_threshold: 100
    look_back_time: 1000000

With the configuration above, the detector will behave as follows once the UDP flood attack starts:
1. The `IP:port` pairs is read by the detector from the FIFO file.
1. The detector consolidates single ports into ranges as they are read from the FIFO file. 
1. When the detector reads 50 new `IP:port` pairs (`ports_attacked_threshold: 50`), the detector sends the first blacklist remediation message which includes all 50 ports, consolidated into ranges.
1. Subsequently, each time 100 new ports are read from the FIFO file, the detector sends another blacklist remediation message.
1. If the detector sees more than 100 new ports (`new_port_count_threshold: 100`) per 1 second interval (`look_back_time: 1000000`) or there are more than 200 `IP:port` read from the FIFO file (`packets_per_interval_threshold: 200`) during 1 second interval (`look_back_time: 1000000`), the detector sends a whitelist remediation message
    -  Included in 200 may be ports that have already been seen
1. No message is sent after the whitelist is sent.


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

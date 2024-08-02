`Iptables Controller` is a Python script meant to provide a functional example of handling alert messages from [ICMP Detector](../detector/README.md).  It works as a TCP server and waits for alert messages from clients.  Alert messages are lines of `csv` data, and `IPtables Controller` processes a single line at a time.

As the name indicates, `IPtables Controller` interacts with `iptables` on the local host, i.e., `src-mec` in the included docker network.  Specifically, for each line of `csv` data, it creates and adds a packet filtering rule in the `FORWARD` chain of the `filter` table.  If the data is for a blacklisted ip address, a `DROP` rule is added.  If the data is for a whitelisted entry, a `PERMIT` rule is added followed by a `DROP-all` rule, so that only the whitelisted packets are allowed to pass through.

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

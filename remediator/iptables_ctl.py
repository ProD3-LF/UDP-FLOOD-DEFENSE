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

"""
This module:
- Receves blacklist and whilist rules from clients
- Applies the received rules to the local 'iptables'

To insert and delete rules, this module runs 'iptables' as a 'subprocess'

This module should be run on the `src-mec` container
"""

import asyncio
import ipaddress
import subprocess
import sys

import netifaces

from async_base_ctl import AsyncBaseController
from client_data_parser import ACTION, IPADDR, PORT_FROM, PORT_TO, PROTO


# iptables tables and chain being used
TABLE = "filter"
CHAIN = "FORWARD"


class IptablesController(AsyncBaseController):
    """
    This class runs 'iptables' to apply filtering rules:
    - table: 'filter'
    - chain: 'FORWARD'
    """

    def __init__(self, loop):
        super().__init__(loop)
        self.access_network_interface = self.get_access_network_interface()
        if self.access_network_interface:
            self.logger.info(
                "Access network interface: %s", self.access_network_interface
            )
        else:
            self.logger.error(
                "No access network interface found: subnet=%s",
                self.access_network_subnet,
            )
        self.blacklist_rules = (
            []
        )  # element: (ipaddr, proto, port_to, port_from)
        self.whitelist_rules = (
            []
        )  # element: (ipaddr, proto, port_to, port_from)

    # pylint: disable=c-extension-no-member
    def get_access_network_interface(self):
        """Find the local interface to which to apply filtering rules via iptables"""
        subnet = ipaddress.ip_network(self.access_network_subnet)
        for iface in netifaces.interfaces():
            for addr_family, ipaddrs in netifaces.ifaddresses(iface).items():
                if addr_family == netifaces.AF_INET:
                    for ipaddr in ipaddrs:  # ipaddrs is a list, ipaddr a dict
                        ip_addr = ipaddress.ip_address(ipaddr.get("addr"))
                        if ip_addr in subnet:
                            return iface
        return None

    def run_cmd(self, cmd):
        """Run a iptables command as a subprocess"""
        self.logger.debug("Running: %s", cmd)
        results = subprocess.run(
            cmd, capture_output=True, text=True, check=False
        )
        if results.stderr:
            self.logger.error(
                "Error: exit=%d, error=%s", results.returncode, results.stderr
            )
        elif results.stdout:
            self.logger.debug("---> %s", results.stdout)

    def iptables_list(self):
        """List all the existing rules currently in place"""
        cmd = ["iptables", "-t", TABLE, "-L", CHAIN, "-n"]
        self.run_cmd(cmd)

    def iptables_allow(self, dst=None, proto="udp", port_from=0, port_to=0):
        """Insert an ACCEPT rule"""
        cmd = ["iptables", "-t", TABLE, "-L", CHAIN, "-n"]
        if int(port_from) > int(port_to):
            self.logger.error(
                "Invalid destination ports: (%d:%d)", port_from, port_to
            )
            return
        cmd = [
            "iptables",
            "-t",
            TABLE,
            "-A",
            CHAIN,
            "-i",
            self.access_network_interface,
            "-d",
            dst,
            "-p",
            proto,
            "--dport",
            f"{port_from}:{port_to}",
            "-j",
            "ACCEPT",
        ]
        self.run_cmd(cmd)

    def iptables_drop(self, dst=None, proto="udp", port_from=0, port_to=0):
        """Insert a DROP rule"""
        cmd = [
            "iptables",
            "-t",
            TABLE,
            "-A",
            CHAIN,
            "-i",
            self.access_network_interface,
            "-d",
            dst,
            "-p",
            proto,
            "--dport",
            f"{port_from}:{port_to}",
            "-j",
            "DROP",
        ]
        self.run_cmd(cmd)

    def iptables_drop_all(self):
        """Insert a DROP-all rule"""
        cmd = [
            "iptables",
            "-t",
            TABLE,
            "-A",
            CHAIN,
            "-i",
            self.access_network_interface,
            "-j",
            "DROP",
        ]
        self.run_cmd(cmd)

    def iptables_delete_drop_all(self):
        """Delete a DROP-all rule"""
        cmd = [
            "iptables",
            "-t",
            TABLE,
            "-D",
            CHAIN,
            "-i",
            self.access_network_interface,
            "-j",
            "DROP",
        ]
        self.run_cmd(cmd)

    def iptables_clear(self):
        """Delete all the existing rules"""
        cmd = ["iptables", "-t", TABLE, "-F", CHAIN]
        self.run_cmd(cmd)

    def proc_blacklist_rule(self, rule):
        """
        1. Insert the new DROP rule
        2. Append the DROP rule data to the list of the existing DROP rules
        """
        if self.whitelist_rules:
            self.logger.debug(
                "Whitelist already in place, cannot apply rule:%s", rule
            )
            return

        dst = rule.get(IPADDR)
        proto = rule.get(PROTO)
        port_from = int(rule.get(PORT_FROM))
        port_to = int(rule.get(PORT_TO))

        self.iptables_drop(
            dst=dst, proto=proto, port_from=port_from, port_to=port_to
        )

        self.blacklist_rules.append((dst, proto, port_from, port_to))

    def proc_whitelist_rule(self, rule):
        """
        1. Delete the "BLOCK ALL" rule if one exists
        2. Insert the new ACCEPT rule
        3. Insert the "BLOCK ALL" rule
        4. Append the ACCEPT rule data to the list of the existing ACCEPT rules
        """
        if self.blacklist_rules:
            self.iptables_clear()
            self.blacklist_rules = []

        dst = rule.get(IPADDR)
        proto = rule.get(PROTO)
        port_from = int(rule.get(PORT_FROM))
        port_to = int(rule.get(PORT_TO))

        if (dst, proto, port_from, port_to) in self.whitelist_rules:
            # Don't insert the same whitelist rule
            return

        if self.whitelist_rules:
            self.iptables_delete_drop_all()

        self.iptables_allow(
            dst=dst, proto=proto, port_from=port_from, port_to=port_to
        )
        self.iptables_drop_all()

        self.whitelist_rules.append((dst, proto, port_from, port_to))

    async def handle_rules(self):
        """
        Coroutine to wait for rules from clients and apply them to 'iptables'
        """
        self.logger.info("Clearing iptables")
        self.iptables_clear()
        while True:
            rule = await self.next_rule()
            if int(rule.get(ACTION)) == 0:
                self.proc_blacklist_rule(rule)
            else:
                self.proc_whitelist_rule(rule)
            self.iptables_list()


if __name__ == "__main__":
    iptables_ctl = IptablesController(asyncio.get_event_loop())
    ret = iptables_ctl.run()
    RETVAL = 0 if ret else 1
    iptables_ctl.logger.info(
        "%s is about to exit with %d", IptablesController.__name__, RETVAL
    )
    sys.exit(RETVAL)

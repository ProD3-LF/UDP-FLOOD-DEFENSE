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
This module provides a data parser for 'blacklist' and 'whitelist' rules,
which are lines of CSV data
"""

import csv


# CSV data fields from clients
TS = "timestamp"
ACTION = "action"  # '0': Block, '1': Whitelist
IPADDR = "ip"  # ipv4 addr
PORT_FROM = "port_from"
PORT_TO = "port_to"
PROTO = "proto"


class ClientDataParser:
    """Parser for blacklist and whitelist rules"""

    def __init__(self, logger):
        self.logger = logger

    def parse_client_data(self, data):
        """
        - 'data' is a sequence of CSV entries (separated by '\n')
        - They are all either 'drop' or 'allow' rules
        - The rules may have different values for 'IPADDR'
        """
        rules = []  # list of Dict
        field_names = [
            TS,
            ACTION,
            IPADDR,
            PORT_FROM,
            PORT_TO,
            PROTO,
        ]
        for msg in data.split("\n"):
            reader = csv.DictReader(iter([msg]), fieldnames=field_names)
            for row in reader:
                if self.is_valid_rule(row):
                    rules.append(row)
                else:
                    self.logger.debug(f"Invalid rule: {row}")
        return rules

    # pylint: disable=too-many-return-statements
    def is_valid_rule(self, rule):
        """
        Checks if a rule has all the required fields and value types
        """
        action = rule.get(ACTION)
        dst = rule.get(IPADDR)
        proto = rule.get(PROTO)
        port_from = rule.get(PORT_FROM)
        port_to = rule.get(PORT_TO)

        if dst is None:
            self.logger.error(f"No dest ip addr in rule: {rule}")
            return False

        if proto is None:
            self.logger.error(f"No proto in rule: {rule}")
            return False

        if int(proto) not in (6, 17):
            self.logger.error(f"Invalid proto in rule: {rule}")
            return False

        if port_from is None:
            self.logger.error(f"No port_from in rule: {rule}")
            return False

        if not port_from.isdigit():
            self.logger.error(f"Invalid port_from in rule: {rule}")
            return False

        if port_to is None:
            self.logger.error(f"No port_to in rule: {rule}")
            return False

        if not port_to.isdigit():
            self.logger.error(f"Invalid port_to in rule: {rule}")
            return False

        if action is None:
            self.logger.error(f"No action in rule: {rule}")
            return False

        if not action.isdigit():
            self.logger.error(f"Invalid action in rule: {rule}")
            return False

        action = int(action)
        if action not in (0, 1):
            self.logger.error(f"Invalid action value in rule: {rule}")
            return False

        return True

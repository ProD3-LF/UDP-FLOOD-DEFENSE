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
This module provides the basis for communicating with clients.  Specifially,
it runs the socket server, which receives blacklist and whitelist rules from clients
and handles the received data by parsing, validating and enqueing rules to be applied
"""

import asyncio
import configparser
import functools
import logging
import os
import signal
import sys

from client_data_parser import ACTION, ClientDataParser


# whitelist rules always have a higher priority than blacklist ones
MIN_BLACKLIST_RULE_PRIORITY = 2**16


class AsyncBaseController:
    """
    This class defines a socket server that waits for blacklist and whitelist rules from clients
    and handles them
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self, loop):
        self.loop = loop
        self._terminate_future = self.loop.create_future()
        self._read_config()

        self.parser = ClientDataParser(self.logger)
        self.whitelist_rule_priority = 0
        self.blacklist_rule_priority = MIN_BLACKLIST_RULE_PRIORITY
        self.rules_queue = asyncio.PriorityQueue()
        self.count_blacklist_rules = 0
        self.count_whitelist_rules = 0

    def _read_config(self):
        config_file = os.sep.join(
            [
                os.path.dirname(os.path.abspath(__file__)),
                "..",
                "common",
                "config",
            ]
        )
        config = configparser.ConfigParser(strict=False)
        with open(config_file, "r", encoding="utf-8") as config_stream:
            # The config file doesn't have any sections
            config.read_string("[top]\n" + config_stream.read())

        self.logger = self._setup_logger(
            config.get("top", "remediator_log_level", fallback="info")
        )
        self.remediation_server_ip = config.get(
            "top", "remediation_ip", fallback=None
        )
        self.remediation_port_blacklist = config.get(
            "top", "remediation_port_blacklist", fallback=None
        )
        self.remediation_port_whitelist = config.get(
            "top", "remediation_port_whitelist", fallback=None
        )
        self.access_network_subnet = config.get(
            "top", "access_network_subnet", fallback=None
        )

        if self.remediation_server_ip is None:
            self.logger.error("No server ip address config found")
            sys.exit(1)

        if self.remediation_port_blacklist is None:
            self.logger.error("No blacklist port config found")
            sys.exit(1)

        if self.remediation_port_whitelist is None:
            self.logger.error("No whitelist port config found")
            sys.exit(1)

        if self.remediation_port_blacklist == self.remediation_port_whitelist:
            self.logger.error(
                "Blacklist and whitelist ports cannot have the same value %d",
                self.remediation_port_whitelist,
            )
            sys.exit(1)

        if self.access_network_subnet is None:
            self.logger.error("No access network subnet config found")
            sys.exit(1)

    def _setup_logger(self, config_log_level="info"):
        log_level = None
        tmp_log_level = config_log_level.upper()

        if tmp_log_level.startswith("DEBUG"):
            log_level = logging.DEBUG
        elif tmp_log_level.startswith("INFO"):
            log_level = logging.INFO
        elif tmp_log_level.startswith("WARN"):
            log_level = logging.WARNING
        elif tmp_log_level.startswith("ERR"):
            log_level = logging.ERROR
        elif tmp_log_level.startswith("CRIT"):
            log_level = logging.CRITICAL

        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        formatter = logging.Formatter(
            "%(asctime)s:%(levelname)s:%(filename)s:%(lineno)d:%(message)s"
        )
        ch.setFormatter(formatter)
        logger = logging.getLogger("remediator")
        logger.setLevel(log_level)
        logger.addHandler(ch)

        return logger

    def run(self):
        """Function that runs coroutes key to the server functions"""
        for signame in ("SIGINT", "SIGTERM"):
            self.loop.add_signal_handler(
                getattr(signal, signame),
                functools.partial(self.handle_signal, signame),
            )

        # Schedule the message handler
        asyncio.ensure_future(self.handle_rules())

        # Schedule the message receiver
        asyncio.ensure_future(self.receive_data())

        # Start the event loop. This should not return unless we're
        # ready to terminate.
        fut = asyncio.ensure_future(self._run(), loop=self.loop)
        self.loop.run_until_complete(fut)
        return fut.result()

    def handle_signal(self, signame):
        """
        Invoked when SIGINT or SIGTERM is received, this function allows the coroutines
        (and the process) to exit gracefully, i.e., without generating exceptions
        """
        try:
            self._terminate_future.set_result(f"Received signal: {signame}")
            self.logger.info(
                "Rules: blacklist=%d, whitelist=%d",
                self.count_blacklist_rules,
                self.count_whitelist_rules,
            )
        except asyncio.InvalidStateError:
            pass

    async def _run(self):
        """
        This coroutine waits for a signal to terminate
        (and alloww for the process to exit gracefully)
        """
        # Wait for a terminate flag
        self.logger.info("Waiting for signal")
        await asyncio.wait_for(self._terminate_future, timeout=None)
        try:
            ret = self._terminate_future.result()
        except asyncio.CancelledError as ce:
            ret = None
            self.logger.error("Cancelled: %s", ce)
        except asyncio.InvalidStateError as ise:
            ret = None
            self.logger.error("Invalid state: %s", ise)
        return ret

    async def next_rule(self):
        """
        Coroutine that waits for a rule to become available
        and returns the rule
        """
        priority, rule = (
            await self.rules_queue.get()
        )  # rule = (priority, rule_dict)
        self.logger.debug(
            "Got rule off queue: priority=%s, rule=%s", priority, rule
        )
        return rule

    async def receive_data(self):
        """
        Coroutine that runs the TCP socket servers to read data from clients
        (one for receiving blacklist rules, the other whitelist rules)
        The servers do not send any data to the clients
        """
        server = await asyncio.start_server(
            self.read_client_data,
            self.remediation_server_ip,
            self.remediation_port_blacklist,
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        self.logger.info("Blacklist server serving on %s", addrs)

        whitelist_server = await asyncio.start_server(
            self.read_client_data,
            self.remediation_server_ip,
            self.remediation_port_whitelist,
        )
        whitelist_addrs = ", ".join(
            str(sock.getsockname()) for sock in whitelist_server.sockets
        )
        self.logger.info("Whitelist server serving on %s", whitelist_addrs)
        async with server, whitelist_server:
            await server.serve_forever()
            await whitelist_server.serve_forever()

    async def read_client_data(self, reader, _):
        """
        Coroutine that reads and handles data from a client
        """
        data_buf = bytearray()
        while not reader.at_eof():
            curr_byte = await reader.read(n=1)  # Read one byte at a time
            data_buf += bytearray(curr_byte)
            if curr_byte == b"\n":  # handle a single line at a time
                data = data_buf.decode().strip()
                if data:
                    self.handle_client_data(data)
                    data_buf = bytearray()

        if data_buf:
            # Handle any leftovers
            data = data_buf.decode().strip()
            self.handle_client_data(data)

    def handle_client_data(self, data):
        """
        Function that parses a rule from client data and enqueues it into a priority queue
        NOTE: a whitelist rule always has a higher priority than a blacklist rule
            and is thus handled before any blacklist rule
        """
        rules = self.parser.parse_client_data(data)
        for rule in rules:
            if int(rule.get(ACTION)) == 0:
                self.count_blacklist_rules += 1
                self.blacklist_rule_priority += 1
                self.rules_queue.put_nowait(
                    (self.blacklist_rule_priority, rule)
                )
            else:
                self.count_whitelist_rules += 1
                self.whitelist_rule_priority += 1
                self.rules_queue.put_nowait(
                    (
                        self.whitelist_rule_priority
                        % MIN_BLACKLIST_RULE_PRIORITY,
                        rule,
                    )
                )
                self.logger.info(
                    "whitelist_rules_count=%d, blacklist_rules_count=%d",
                    self.count_whitelist_rules,
                    self.count_blacklist_rules,
                )

    async def handle_rules(self):
        """
        A child class should implement this task
        """
        self.logger.info("Implement Me!")

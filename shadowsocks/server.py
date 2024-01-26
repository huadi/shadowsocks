#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, with_statement

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, asyncdns, manager


def main():
    shell.check_python()
    config = shell.get_config(False)
    daemon.daemon_exec(config)

    config['port_password'] = {}
    server_port = config['server_port']
    config['port_password'][str(server_port)] = config['password']

    if config.get('manager_address', 0):
        logging.info('entering manager mode')
        manager.run(config)
        return

    tcp_servers = []
    udp_servers = []
    dns_resolver = asyncdns.DNSResolver(prefer_ipv6=config['prefer_ipv6'])

    port_password = config['port_password']
    del config['port_password']
    for port, password in port_password.items():
        a_config = config.copy()
        a_config['server_port'] = int(port)
        a_config['password'] = password
        logging.info("starting server at %s:%d" % (a_config['server'], int(port)))
        tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False))
        udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False))

    def run_server():
        def child_handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            list(map(lambda s: s.close(next_tick=True), tcp_servers + udp_servers))
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), child_handler)

        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        try:
            # 启动server的核心逻辑
            loop = eventloop.EventLoop()
            dns_resolver.add_to_loop(loop)
            list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))
            daemon.set_user(config.get('user', None))
            loop.run()
        except Exception as e:
            shell.print_exception(e)
            sys.exit(1)

    run_server()


if __name__ == '__main__':
    main()

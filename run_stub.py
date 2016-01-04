#!/usr/bin/env python3

import subprocess as sp

SOCKS4_PROXY_PORT = 8081
SOCKS5_PROXY_PORT = 8080
TCP_ECHO_SERVER_PORT = 5000

sp.Popen(["./socks_stub_server.py", str(SOCKS5_PROXY_PORT)])
sp.Popen(["./socks_stub_server.py", str(SOCKS4_PROXY_PORT), "v4"])
sp.Popen(["./tcp_echo_server.py", str(TCP_ECHO_SERVER_PORT)])

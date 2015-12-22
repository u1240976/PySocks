#!/usr/bin/env python3

import sys
import socket

def tcp_echo_server(server_ip, server_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)

    while 1:
        connection_socket, addr = server_socket.accept()
        msg = connection_socket.recv(1024)
        connection_socket.send(msg)

    connection_socket.close()

if __name__ == '__main__':
    port = 5000
    if len(sys.argv) >= 2:
        port = int(sys.argv[1])

    tcp_echo_server("localhost", port)

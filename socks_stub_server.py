#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
Simple Socks Server implementation from http://code.google.com/p/python-socks5
Use it as a stub for testing.
"""

import socket
from threading import Thread
import sys
import signal

SOCKTIMEOUT=5     # client connection timeout (sec)
RESENDTIMEOUT=300 # resend timeout (sec)

VER="\x05"
METHOD="\x00"

SUCCESS="\x00"
SOCKFAIL="\x01"
NETWORKFAIL="\x02"
HOSTFAIL="\x04"
REFUSED="\x05"
TTLEXPIRED="\x06"
UNSUPPORTCMD="\x07"
ADDRTYPEUNSPPORT="\x08"
UNASSIGNED="\x09"

_LOGGER=None

# Logger
class Log:
    WARN="[WARN:]"
    INFO="[INFO:]"
    ERROR="[ERROR:]"
    def write(self,message,level):
        pass
        
class SimpleLog(Log):
    import sys
    def __init__(self,output=sys.stdout):
        self.__output=output
        self.show_log=True
        
    def write(self,message,level=Log.INFO):
        if self.show_log:
            self.__output.write("%s\t%s\n" %(level,message))
            
def getLogger(output=sys.stdout):
    global _LOGGER
    if not _LOGGER:
        _LOGGER=SimpleLog(output)
    return _LOGGER
        
# Socks Proxy
class SocketTransform(Thread):
    """
    Proxy Implementation: using 2 threads.
    """
    def __init__(self,src,dest_ip,dest_port,bind=False):
        Thread.__init__(self)
        self.dest_ip=dest_ip
        self.dest_port=dest_port
        self.src=src
        self.bind=bind
        self.setDaemon(True)

    def run(self):
        try:
            self.resend()
        except Exception,e:
            getLogger().write("Error on SocketTransform %s" %(e.message,),Log.ERROR)
            self.sock.close()
            self.dest.close()

    def resend(self):
        """
        Running 2 threads: 

            First one read sock socket and write dest socket
            Another one read dest socket and write dest socket
        """
        self.sock=self.src
        self.dest=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.dest.connect((self.dest_ip,self.dest_port))
        if self.bind:
            getLogger().write("Waiting for the client")
            self.sock,info=sock.accept()
            getLogger().write("Client connected")
        getLogger().write("Starting Resending")
        self.sock.settimeout(RESENDTIMEOUT)
        self.dest.settimeout(RESENDTIMEOUT)

        # 2 threads:
        #   self.sock => self.dest
        #   self.dest => self.sock
        Resender(self.sock, self.dest).start()
        Resender(self.dest, self.sock).start()


class Resender(Thread):
    """
    Running a thread to continuously read from src socket and write to dest socket.

    src socket => dst socket
    """
    def __init__(self,src,dest):
        Thread.__init__(self)
        self.src=src
        self.setDaemon(True)
        self.dest=dest

    def run(self):
        try:
            self.resend(self.src,self.dest)
        except Exception,e:
            getLogger().write("Connection lost %s" %(e.message,),Log.ERROR)
            self.src.close()
            self.dest.close()

    def resend(self,src,dest):
        data=src.recv(10)
        while data:
            dest.sendall(data)
            data=src.recv(10)
        src.close()
        dest.close()
        getLogger().write("Client quit normally\n")

def create_server(ip,port):
    """
    create Socks v5 Server

    feature: listen multiple connection, multithread-based server
    Proxy implementation is based on SocketTransform class
    TODO: BIND, UDP Commands, Authentication
    """
    transformer=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    transformer.bind((ip,port))
    signal.signal(signal.SIGTERM,OnExit(transformer).exit)
    transformer.listen(1000)

    while True:
        sock,addr_info=transformer.accept()
        sock.settimeout(SOCKTIMEOUT)
        getLogger().write("Got one client connection")

        try:
            # Auth method
            # | VER | NMETHODS | METHODS |
            ver,nmethods,methods=(sock.recv(1),sock.recv(1),sock.recv(1))
                # auth response
                # | VER | METHOD |
            sock.sendall(VER+METHOD)
            
            # Socks Request
            # | VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
            ver,cmd,rsv,addr_type=(sock.recv(1),sock.recv(1),sock.recv(1),sock.recv(1))
            dst_addr=None
            dst_port=None
            
            # parse destination address
            if addr_type=="\x01": 
                # IPv4
                dst_addr,dst_port=sock.recv(4),sock.recv(2)
                dst_addr=".".join([str(ord(i)) for i in dst_addr])
            elif addr_type=="\x03": 
                # Domain Name
                addr_len=ord(sock.recv(1)) # length of domain name
                dst_addr,dst_port=sock.recv(addr_len),sock.recv(2)
                dst_addr="".join([unichr(ord(i)) for i in dst_addr])
            elif addr_type=="\x04":
                # IPv6
                dst_addr,dst_port=sock.recv(16),sock.recv(2)
                tmp_addr=[]
                for i in xrange(len(dst_addr)/2):
                    tmp_addr.append(unichr(ord(dst_addr[2*i])*256+ord(dst_addr[2*i+1])))
                dst_addr=":".join(tmp_addr)

            dst_port=ord(dst_port[0])*256+ord(dst_port[1])

            getLogger().write("Client wants to connect to %s:%d" %(dst_addr,dst_port))
            server_sock=sock
            server_ip="".join([chr(int(i)) for i in ip.split(".")])

            # processing Socks Request Commands
            if cmd=="\x01":
                # CONNECT Command
                sock.sendall(VER+SUCCESS+"\x00"+"\x01"+server_ip+chr(port/256)+chr(port%256))
                getLogger().write("Starting transform thread")
                SocketTransform(server_sock,dst_addr,dst_port).start()
            elif cmd=="\x02":
                # TODO: BIND Command
                sock.close()
            elif cmd=="\x03":
                # TODO: UDP ASSOCIATE Command
                sock.close()
            else:
                # Unsupported Command
                sock.sendall(VER+UNSPPORTCMD+server_ip+chr(port/256)+chr(port%256))
                sock.close()

        except Exception,e:
            getLogger().write("Error on starting transform:"+e.message,Log.ERROR)
            sock.close()

class OnExit:
    def __init__(self,sock):
        self.sock=sock

    def exit(self):
        self.sock.close()


if __name__=='__main__':
    try:
        ip="0.0.0.0"
        port=8080
        create_server(ip,port)
    except Exception,e:
        getLogger().write("Error on create server:"+e.message,Log.ERROR)


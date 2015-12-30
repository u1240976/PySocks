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
import traceback

SOCKTIMEOUT=5     # client connection timeout (sec)
RESENDTIMEOUT=300 # resend timeout (sec)

VER="\x05"
METHOD="\x00"
NULBYTE='\x00'
SOCKS4A_ACCEPT='\x5a'

SUCCESS="\x00"
SOCKFAIL="\x01"
NETWORKFAIL="\x02"
HOSTFAIL="\x04"
REFUSED="\x05"
TTLEXPIRED="\x06"
UNSUPPORTCMD="\x07"
ADDRTYPEUNSPPORT="\x08"
UNASSIGNED="\x09"
USERID = bytearray("TEST")
USERNAME = "USERNAME"
PASSWORD = "PASSWORD"

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
        except Exception as e:
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
        self.dest.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        except Exception as e:
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
    transformer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
            # Only accept username:password for now ...
            for methodIter in methods :
                if methodIter == '\x02' :
                    # Change Auth Method
                    METHOD = '\x02'
                    break
            sock.sendall(VER+METHOD)

            if METHOD = '\x02':
            #AUTH is set, get username:password pair and check...
                ver,userlen=(sock.recv(1),sock.recv(1))
                if ver != '\x01':
                    # Strictly reject authentication with wrong version number
                    sock.sendall(VER+'\x01')
                userlen  = ord(userlen)
                username = "".join([unichr(ord(i)) for i in sock.recv(userlen)])
                passlen  = ord(userlen)
                password = "".join([unichr(ord(i)) for i in sock.recv(passlen)])

                if username ==  USERNAME and password == PASSWORD :
                    sock.sendall(VER+'\x00')
                else :
                    sock.sendall(VER+'\x01')
            
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
                # Simply fake the response since we made an echo server on localhost
                sock.sendall(VER+SUCCESS+"\x00"+"\x01"+server_ip+chr(port/256)+chr(port%256))
                getLogger().write("Starting transform thread")
                SocketTransform(server_sock,"127.0.0.1",dst_port).start()
            elif cmd=="\x03":
                # TODO: UDP ASSOCIATE Command
                sock.close()
            else:
                # Unsupported Command
                sock.sendall(VER+UNSPPORTCMD+server_ip+chr(port/256)+chr(port%256))
                sock.close()

        except Exception as e:
            getLogger().write("Error on starting transform:"+e.message,Log.ERROR)
            sock.close()

def create_server_4a(ip,port):

    transformer=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    transformer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    transformer.bind((ip,port))
    signal.signal(signal.SIGTERM,OnExit(transformer).exit)
    transformer.listen(1000)

    while True:
        sock,addr_info=transformer.accept()
        sock.settimeout(SOCKTIMEOUT)
        getLogger().write("Got one client connection")

        try:
            # Auth method
            # | VER | CMD | PORT | DISTIP | UID
            Ver,Cmd,Port,DistIP=(sock.recv(1),sock.recv(1),sock.recv(2),sock.recv(4))

            Port = ord(Port[0])*256+ord(Port[1])
            DNSForward = False

            # Accroding to SOCKS4a, if DISTIP in the form of "0.0.0.x", handle DNS
            if (DistIP[0] == DistIP[1] == DistIP[2] == b'\x00') and (DistIP[3] != b'\x00') :
                DNSForward = True
            else :
                DistIP=".".join([str(ord(i)) for i in DistIP])

            _SockUserID = []
            while unichr(ord(sock.recv(1))) != b'\x00' :
                _SockUserID.append(unichr(ord(sock.recv(1))))
            UserID = "".join(_SockUserID)

            _DomainName= []
            if DNSForward:
                while unichr(ord(sock.recv(1))) != b'\x00' :
                    _DomainName.append(unichr(ord(sock.recv(1))))
                DomainCon = "".join(_DomainName)
            if AuthRequest :
                if UserID == sys.argv[3]:
                    pass
                else :
                    # Status Code 0x5b means this request is rejected by server
                    sock.sendall(NULBYTE + b'\x5b' + server_ip + chr(port/256)+chr(port%256))
                    
                

            # auth response
            # | NULBYTE | STATUS | SERVERIP | SERVER PORT
            # Assuming recieved a valid user id
            server_ip="".join([chr(int(i)) for i in ip.split(".")])
            server_sock=sock

            # processing Socks Requested Commands
            if Cmd == "\x01":
                # CONNECT Command
                sock.sendall(NULBYTE + SOCKS4A_ACCEPT + server_ip + chr(port/256)+chr(port%256))

                if DNSForward:
                    SocketTransform(server_sock,DomainCon,Port).start()
                else :
                    SocketTransform(server_sock,DistIP,Port).start()
                    
                getLogger().write("Starting transform thread")
            elif Cmd == "\x02":
                # TODO: BIND Command
                sock.sendall(NULBYTE + SOCKS4A_ACCEPT + server_ip + chr(port/256)+chr(port%256))
                sock.close()
            else:
                # Unsupported Command
                sock.sendall(NULBYTE + SOCKS4A_ACCEPT + server_ip + chr(port/256)+chr(port%256))
                sock.close()

        except Exception as e:
            exc_info = sys.exc_info()
            traceback.print_exception(*exc_info)
            getLogger().write("Error on starting transform: "+str(type(e))+e.message, Log.ERROR)
            sock.close()

class OnExit:
    def __init__(self,sock):
        self.sock=sock

    def exit(self):
        self.sock.close()


if __name__=='__main__':
    try:
        if len(sys.argv) < 2:
            print("./socks_stub_server <port> <version>")
        
        ip="0.0.0.0"
        port=int(sys.argv[1])

        if len(sys.argv) == 3 and sys.argv[2] == 'auth':
            AuthRequest = True

        if len(sys.argv) >= 3 and sys.argv[2] == "v4":
            create_server_4a(ip,port)
        else:
            create_server(ip,port)
    except Exception as e:
        getLogger().write("Error on create server:"+e.message,Log.ERROR)


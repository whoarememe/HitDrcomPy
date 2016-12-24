#coding:utf-8

import socket
import fcntl
from struct import *

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, 
        pack('256s', ifname[:15].encode('utf-8')))[20:24])

def test_connecting():
    import os
    r = os.system("ping www.baidu.com -c 3")
    return r
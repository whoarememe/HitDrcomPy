#coding:utf-8

from eap_auth import *
from udp_auth import *
from udp_alive import *
from config import *
import socket
import time
import sys, signal, os
import utils

eapauth = ""
udpauth = ""
#  udp_alive = ""

def quit(signum, frame):
    global eapauth
    global udpauth

    try:
        eapauth.end()
        eapauth.close_socket()
        udpauth.logoff()
    except:
        pass

    color_print.warning("quit")
    sys.exit()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, quit)
    signal.signal(signal.SIGTERM, quit)

    #定义默认超时时间
    socket.setdefaulttimeout(1)
    #初始化nic_info,可以获取指定网卡的一些信息
    nic_in = utils.nic_info(CON_IFNAME)
    #udp套接字
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #绑定本地ip和端口
    udp_client.bind((nic_in.get_local_ip(), nic_in.get_local_port()))
    #连接服务器的ip和端口
    udp_client.connect((nic_in.get_server_ip(), nic_in.get_server_port()))

    #-----学生区------
    #eapauth = eap_auth(CON_ACCOUNT, CON_PASSWORD, nic_in)
    # # eapauth.logoff()
    #if eapauth.start_auth():
    #    setp4 = alive_step(udp_client, nic_in, eapauth)

    #    setp4.setDaemon(True)
    #    setp4.start()

    #while True:
    #    time.sleep(10)
    #    pass

    #----教学区----
    #udp认证
    udpauth = udp_auth(udp_client, CON_ACCOUNT, CON_PASSWORD, nic_in)
    if udpauth.start_auth():
        # print("main len: " + str(len(udpauth.get_md5a())))
        #
        alive20 = udp_alive(nic_in, udp_client, udpauth)
        setp4 = alive_step(udp_client, nic_in, udpauth)

        alive20.setDaemon(True)
        setp4.setDaemon(True)
        alive20.start()
        #time.sleep(2)
        setp4.start()

    while True:
        time.sleep(10)
        pass

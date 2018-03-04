#coding:utf-8

# from eap_auth import *
# from udp_auth import *
# from udp_alive import *
# from config import *
# import socket
# import time
# import sys, signal, os
# import utils

# eapauth = ""
# udpauth = ""
# udp_alive = ""

# def quit(signum, frame):
#     global eapauth
#     global udpauth

#     eapauth.end()
#     eapauth.close_socket()

#     color_print.warning("quit")
#     sys.exit()

# signal.signal(signal.SIGINT, quit)
# signal.signal(signal.SIGTERM, quit)

# socket.setdefaulttimeout(1)
# nic_in = utils.nic_info(CON_IFNAME)

# eapauth = eap_auth(CON_ACCOUNT, CON_PASSWORD, nic_in)

# # eapauth.logoff()
# udp_alive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# udp_alive.bind((nic_in.get_local_ip(), nic_in.get_local_port()))
# udp_alive.connect((nic_in.get_server_ip(), nic_in.get_server_port()))

# if eapauth.start_auth():
#     setp4 = alive_step(udp_alive, nic_in, eapauth)

#     setp4.setDaemon(True)
#     setp4.start()

# while True:
#     time.sleep(10)
#     pass

class StuDist:
    def __init__(self):
        pass

class WorkDist:
    def __init__(self):
        pass


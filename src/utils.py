#coding:utf-8

import socket
import fcntl
from struct import *
from ctypes import *
import time

class nic_info():
    def __init__(self, nic):
        self.__nic = nic
        self.__local_mac = ""
        # 192.168.1.1形式
        self.__local_ip = ""
        self.__local_port = 61440
        self.__server_ip = "172.25.8.4"
        self.__server_port = 61440

        pass

    def get_ifname(self):
        return self.__nic

    def get_local_mac(self):
        if self.__local_mac:
            pass
        else:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
            s.bind((self.__nic, 0x888e))
            self.__local_mac = s.getsockname()[4]
            # s.shutdown()
            s.close()

        return self.__local_mac

    def get_local_ip(self):
        if self.__local_ip:
            pass
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.__local_ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, pack('256s', self.__nic[:15].encode('utf-8')))[20:24])
            # print self.__local_ip
            # s.shutdown()
            s.close()

        return self.__local_ip

    def get_local_port(self):
        return self.__local_port

    def get_server_ip(self):
        return self.__server_ip

    def get_server_port(self):
        return self.__server_port

class color_print():
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'

    @staticmethod
    def info(data):
        print(color_print.OKBLUE + '[' + time.strftime("%Y-%m-%d %X") + '] - ' + '[INF]'  + data + color_print.END)

    @staticmethod
    def ok(data):
        print(color_print.OKGREEN + '[' + time.strftime("%Y-%m-%d %X") + '] - ' + '[INF]' + data + color_print.END)

    @staticmethod
    def warning(data):
        print(color_print.OKBLUE + '[' + time.strftime("%Y-%m-%d %X") + '] - ' + '[WAR]'  + data + color_print.END)

    @staticmethod
    def error(data):
        print(color_print.ERROR + '[' + time.strftime("%Y-%m-%d %X") + '] - ' + '[ERR]'  + data + color_print.END)

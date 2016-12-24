#coding:utf-8

import socket
import hashlib
from struct import *
from utils import *

MULTICAST_ADDR = "\x01\x80\xc2\x00\x00\x03"
BROADCAST = "\xff\xff\xff\xff\xff\xff"
RESPONSE_ID_FIXED = "\x00\x44\x61\x00\x00"
RESPONSE_MD5_FIXED = "\x00\x44\x61\x0c\x00"

ETH_TYPE = 0x888e
EAPOL_VERSION = 0x01
EAPOL_PACKET = 0x00
EAPOL_START = 0x01
EAPOL_LOGOFF = 0x02
EAP_REQUEST = 0x01
EAP_RESPONSE = 0x02
EAP_SUCCESS = 0x03
EAP_FAILURE = 0x04
EAP_DATA_TYPE_IDENTITY = 0x01
EAP_DATA_TYPE_NOTIF = 0x02
EAP_DATA_TYPE_MD5 = 0x04

def eth_header(dst_mac, src_mac):
    return dst_mac + src_mac + pack("!H", ETH_TYPE)

def eapol_header(pkt_type, data=""):
    if pkt_type in [EAPOL_START, EAPOL_LOGOFF]:
        return pack("!BBH", EAPOL_VERSION, pkt_type, 0)
    else:
        return pack("!BBH", EAPOL_VERSION, EAPOL_PACKET, len(data)) + data

def eap_header(code, id, data=""):
    if code in [EAP_SUCCESS, EAP_FAILURE]:
        return pack("!BBH", code, id, 0x0004)
    else:
        return pack("!BBH", code, id, 4+len(data)) + data # + pack("!B", 0x00)*54

def eap_header_data(data_type, data=""):
    return pack("!B", data_type) + data

class eap_dealer:
    __request_id_id = 0
    __auth_success = False
    __md5_chanllenge = ""
    __md5_len = 0
    __dst_mac = MULTICAST_ADDR

    def __init__(self, username, password, nic, local_mac = "", ip_addr = ""):
        self.client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE))
        self.client.bind((nic, ETH_TYPE))
        if not local_mac:
            self.local_mac = self.client.getsockname()[4]
        else:
            self.local_mac = local_mac
        if ip_addr:
            self.local_ip = ip_addr
        else:
            self.local_ip = get_ip_address(nic)        
        self.username = username
        self.password = password

        # self.eth_h = eth_header(self.local_mac)
    def start(self):
        pkt_start = eth_header(self.__dst_mac, self.local_mac) + eapol_header(0x01)
        self.client.send(pkt_start)

    def logoff(self):
        pkt_logoff = eth_header(self.__dst_mac,self.local_mac) + eapol_header(0x02)
        self.client.send(pkt_logoff)
        self.__auth_success = False

    def response_id(self):
        # response_data = 
        pkt_response_id = eth_header(self.__dst_mac, self.local_mac) + eapol_header(0x00, 
            data=eap_header(0x02, self.__request_id_id, 
            data=eap_header_data(EAP_DATA_TYPE_IDENTITY, 
            data=self.get_response_id_addition())))

        self.client.send(pkt_response_id)

    def get_response_id_addition(self):
        return self.username + RESPONSE_ID_FIXED + socket.inet_aton(self.local_ip)

    def response_md5(self):
        print("2***************************", self.__request_id_id)
        pkt_response_md5 = eth_header(self.__dst_mac, self.local_mac) + eapol_header(0x00,
            data=eap_header(0x02, self.__request_id_id, 
            data=eap_header_data(EAP_DATA_TYPE_MD5, 
            data=self.get_md5_info())))

        self.client.send(pkt_response_md5)
    
    def get_response_md5_addition(self):
        return self.username + RESPONSE_MD5_FIXED + socket.inet_aton(self.local_ip)

    def get_md5_info(self):
        char_b = bytearray()

        char_b.append(self.__request_id_id)
        for i in range(0, len(self.password)):
            char_b.append(ord(self.password[i]))
        for i in range(0, self.__md5_len):
            char_b.append(self.__md5_chanllenge[i])

        m2 = hashlib.md5()
        m2.update(char_b)
        d = m2.digest()
        return pack("!B", len(d)) + d + self.get_response_md5_addition() # + pack("!B", 0x00)*38

    def deal_recv(self, recv):
        ver, pkt_type, length = unpack("!BBH", recv[0:4])
        if pkt_type == EAPOL_PACKET:
            print("i am pkt")
            eap_code, eap_id, eap_len = unpack("!BBH", recv[4:8])
            print("eap code %d", eap_code)
            # 如果是request，记录id
            if eap_code == EAP_REQUEST:
                print("i am eap request")
                self.__request_id_id = eap_id
                # 说明有数据
                if eap_len > 4:
                    eap_data_type, = unpack("!B", recv[8:9])
                    if eap_data_type == EAP_DATA_TYPE_IDENTITY:
                        self.response_id()
                    elif eap_data_type == EAP_DATA_TYPE_MD5:
                        self.__md5_len, = unpack("!B", recv[9:10])
                        self.__md5_chanllenge = recv[10:10+self.__md5_len]
                        self.response_md5()
                    elif eap_data_type == EAP_DATA_TYPE_NOTIF:
                        pass
                    else:
                        pass
                return 1
            elif eap_code == EAP_FAILURE:
                self.__auth_success = False
                return 0
            elif eap_code == EAP_SUCCESS:
                print "i am success"
                self.__auth_success = True
                return 1
            else:
                self.__auth_success = False
                return 0

    def start_auth(self):
        self.logoff()
        self.logoff()
        self.start()

        while True:
            if self.__auth_success:
                self.__auth_success = False
                print "i am break"
                break
            
            recv_pkt = self.client.recv(1600)
            # 超时接收，那么重新连接，继续接收，另开一个线程或者进程专门处理链路层认证
            self.__dst_mac = recv_pkt[6:12]

            if self.deal_recv(recv_pkt[14:]):
                continue
            else:
                self.logoff()
                self.logoff()
                self.start()
                continue

        return True
#coding:utf-8

import socket
import hashlib
import time
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

class eap_auth():
    __request_id_id = 0
    __auth_success = False
    __md5_chanllenge = ""
    __md5_len = 0
    __dst_mac = MULTICAST_ADDR

    def __init__(self, username, password, nic_info):
        self.client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE))
        self.client.bind((nic_info.get_ifname(), ETH_TYPE))

        self.local_mac = nic_info.get_local_mac()
        self.local_ip = nic_info.get_local_ip()
        self.username = username
        self.password = password

        # 超时计数
        self.__timeout_count = 0

        self.__err_pkt = 0
        # self.eth_h = eth_header(self.local_mac)
    def start(self):
        color_print.info("开始EAP认证")
        pkt_start = self.eth_header(self.__dst_mac, self.local_mac) + self.eapol_header(0x01)
        color_print.info("发送EAP认证包")
        try:
            self.client.send(pkt_start)
        except socket.errno:
            colot_print.error("发送EAP失败！")
            raise

    def logoff(self):
        color_print.info("开始LOGOFF")
        pkt_logoff = self.eth_header(self.__dst_mac,self.local_mac) + self.eapol_header(0x02)
        color_print.info("发送LOGOFF请求！")
        self.client.send(pkt_logoff)
        self.__auth_success = False

    def response_id(self):
        color_print.info("准备身份认证")
        pkt_response_id = self.eth_header(self.__dst_mac, self.local_mac) + self.eapol_header(0x00,
            data = self.eap_header(0x02, self.__request_id_id,
            data = self.eap_header_data(EAP_DATA_TYPE_IDENTITY,
            data = self.get_response_id_addition())))

        color_print.info("发送身份认证")
        self.client.send(pkt_response_id)

    def get_response_id_addition(self):
        return self.username + RESPONSE_ID_FIXED + socket.inet_aton(self.local_ip)

    def response_md5(self):
        color_print.info("准备MD5认证")
        pkt_response_md5 = self.eth_header(self.__dst_mac, self.local_mac) + self.eapol_header(0x00,
            data = self.eap_header(0x02, self.__request_id_id,
            data = self.eap_header_data(EAP_DATA_TYPE_MD5,
            data = self.get_md5_info())))

        color_print.info("发送MD5认证")
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
        ver, pkt_type, length, = unpack("!BBH", recv[0:4])
        # just deal pkt, other return
        if pkt_type == EAPOL_PACKET:
            eap_code, eap_id, eap_len = unpack("!BBH", recv[4:8])

            # 如果是request，记录id,只处理request，failure，以及success，其他的返回
            if eap_code == EAP_REQUEST:
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
                        color_print.warning("get eapol pkt and it is request pkt, it send some info to u!")
                        print(recv[9:])
                        pass
                    else:
                        pass
                return 1
            elif eap_code == EAP_FAILURE:
                color_print.error("get eapol pkt, but eap_code failure! sleep 1s")
                # 要不要？？
                # time.sleep(1)
                self.logoff()
                self.before_auth()

                self.__auth_success = False
                return 0
            elif eap_code == EAP_SUCCESS:
                color_print.ok("get eapol pkt, eap_code succes!")
                self.__auth_success = True
                return 1
            else:
                color_print.error("get eapol pkt, but eap_code unknow!")
                # 要不要？？
                # time.sleep(2)
                self.__auth_success = False
                return 1
        # 其他包直接返回
        # else:
            # color_print.error("not eapol pkt type, unknow pkt!")
            # 要不要？？
            # time.sleep(2)
            # return 1

    def eth_header(self, dst_mac, src_mac):
        return dst_mac + src_mac + pack("!H", ETH_TYPE)

    def eapol_header(self, pkt_type, data=""):
        if pkt_type in [EAPOL_START, EAPOL_LOGOFF]:
            return pack("!BBH", EAPOL_VERSION, pkt_type, 0)
        else:
            return pack("!BBH", EAPOL_VERSION, EAPOL_PACKET, len(data)) + data

    def eap_header(self, code, id, data=""):
        if code in [EAP_SUCCESS, EAP_FAILURE]:
            return pack("!BBH", code, id, 0x0004)
        else:
            return pack("!BBH", code, id, 4+len(data)) + data # + pack("!B", 0x00)*54

    def eap_header_data(self, data_type, data=""):
        return pack("!B", data_type) + data

    # end
    def end(self):
        self.logoff()
        self.client.close()

    # close socket
    def close_socket(self):
        self.client.close()

    # before auth
    def before_auth(self):
        time.sleep(1)
        self.__err_pkt = 0

        self.logoff()
        self.logoff()
        self.start()

    def start_auth(self):

        self.before_auth()

        while True:
            if self.__auth_success:
                self.__auth_success = False
                color_print.ok("EAP auth success")
                break

            # if self.__err_pkt > 3:
            #     self.logoff()

            #     self.before_auth()

            try:
                recv_pkt = self.client.recv(1600)
            except socket.timeout:
                color_print.error("recv timeout, retry!")

                self.logoff()

                self.before_auth()
                continue

            if self.local_mac != recv_pkt[0:6]:
                color_print.warning("recv pkt , but not urs!!")
                # self.__err_pkt += 1
                continue

            self.__dst_mac = recv_pkt[6:12]

            self.deal_recv(recv_pkt[14:])

            # if self.deal_recv(recv_pkt[14:]):
            #     continue
            # else:
            #     self.logoff()

            #     self.before_auth()
            #     continue

        return True

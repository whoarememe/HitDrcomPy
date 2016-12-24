#coding:utf-8

from threading import Lock, Thread
import socket
from utils import *
import time
from struct import *
from config import LOCAL_IP

UDP_ALIVE_CODE = 0xff
CODE_MISC = 0x07
AUTH_TYPE = 0x0800
STEP_TYPE = 0x2800

# 开始认证
# eap认证成功之后首先进行的是这个认证，成功之后分两个线程进行心跳，
# 否则重新链路层认证,我觉得这个东西没用
class udp_auth():
    def __init__(self, udp_client):
        self.client = udp_client
        self.pkt_id = 0
        self.local_ip = LOCAL_IP

    def get_pkt2(self):
        self.pkt_id += 1
        byte_data = bytearray()

        for i in range(0, len(CON_ACCOUNT)):
            byte_data.append(ord(CON_ACCOUNT[i]))
        byte_data.append()
        return CODE_MISC + chr(self.pkt_id) + "\xf4\x00"

    # 要发送的alivepkt
    def get_pkt1(self):
        return CODE_MISC + chr(self.pkt_id) + AUTH_TYPE +\
            "\x01\x00\x00\x00"

    def deal_recv(self, recv_data):
        code_misc, count_what, pkt_type, fix1, fix2, local_ip = \
            unpack("!BBHHII", recv_data[0:17])

        if pkt_type == 0x1000:
            return True
        else:
            return False
        pass

    def auth(self):
        pkt_data = self.get_pkt()
        self.client.send(pkt_data)
        recv_data = self.client.recv(1600)

        # 返回1认证成功，其他认证失败，重新发送此包
        return self.deal_recv(recv_data)
        pass

# 20s定时心跳，暂时没有搞定，没有找到加密方式
class udp_alive(Thread):
    def __init__(self, udp_client):
        self.some_time = 0
        self.client = udp_client

    def get_auth_info(self):
        # Drco + serverIp
        return "\x44\x72\x63\x6f" + \
            socket.aton(SERVER_ADDR) + \
            "\xdb\x55" + \
            socket.aton(LOCAL_IP) + \
            "\x01\x9c"
    def get_time(self):
        self.some_time += 20
        return pack("!H", self.some_time)

    def get_md5_info(self):
        pass

    def get_alive_pkt(self):
        return UDP_ALIVE_CODE + self.get_md5_info() + \
            "\x00\x00\x00" + \
            self.get_auth_info() + \
            self.get_time()
        pass

# 四步心跳
class alive_step(Thread):
    def __init__(self, udp_alive_step):
        self.client = udp_alive_step
        self.pkt_id = 0
        self.per_1000_setp = "\x00\x00"
        self.some_flux = "\x00\x00\x00\x00"
        self.first_pkt = True
        # 使用字符串
        self.client_ip = LOCAL_IP

    def send_pkt1(self, add_one):
        print("send pkt1")
        if add_one:
            if self.pkt_id >= 255:
                self.pkt_id = 0
            else:
                self.pkt_id += 1

        pkt_data = self.get_pkt1()

        print("i will send")
        self.client.send(pkt_data)
        print("send pk1 ok")

        self.first_pkt = False

    def send_pkt3(self, add_one):
        print("send pkt3")
        if add_one:
            if self.pkt_id >= 255:
                self.pkt_id = 0
            else:
                self.pkt_id += 1

        pkt_data = self.get_pkt3()

        self.client.send(pkt_data)

    # 处理接收并发送
    #
    def deal_recv(self, recv_data):
        print("deal recv")
        # code_misc, pkt_id, pkt_type, fix1, pkt_step, fix2, per_1000_step  = unpack("!BBHBBHH", recv_data[0:10])
        code_misc, pkt_id, pkt_type, fix1, pkt_step  = unpack("!BBHBB", recv_data[0:6])
        # 首先判断基本数据是否正确
        print code_misc
        print pkt_type
        
        if code_misc == CODE_MISC and pkt_type == STEP_TYPE:
            print "i am here , and i will de whether pkt id is self.pktid"
            # 判断当前包的id与收到的id是否一样，不一样重新发送第一个包
            if self.pkt_id == pkt_id:
                print "i set the self flux"
                self.some_flux = recv_data[16:20]
                # 第二步
                if pkt_step == 0x02:
                    print "i will send pkt3"
                    self.send_pkt3(True)
                    return 3

                # 第四步，如果到了第四步，那么睡眠20s，然后发送第一个包
                elif pkt_step == 0x04:
                    print "i will sleep 20s"
                    time.sleep(20)
                    print "i will send pkt1"
                    self.send_pkt1(True)
                    return 4
                else:
                    self.send_pkt1(False)
                    return -1
            else:
                print "i will sleep 10"
                time.sleep(2)
                print "i will send pkt1"
                self.send_pkt1(False)
                return

        # 不正确的话重新发送一号包，pkt_id自动加1的，重发的也加1
        else:
            print "i will sleep 10 and then send pkt1"
            time.sleep(2)
            self.send_pkt1(False)
            return

    # int, int, "\x00\x00", "\x00\x00\x00\x00"
    def get_pkt_data(self, pkt_id, step_id, per_1000_setp, some_flux, client_ip):
        # print type(per_1000_setp)
        # print type(some_flux)
        # print type(client_ip)
        # print some_flux

        pkt_data = "\x07" + \
            chr(pkt_id) + \
            "\x28\x00" + \
            "\x0b" + \
            chr(step_id) + \
            "\x1f\x00" + \
            per_1000_setp + \
            "\x00\x00\x00\x00" + \
            "\x00\x00" + \
            some_flux + \
            "\x00\x00\x00\x00\x00\x00\x00\x00" + \
            client_ip + \
            "\x00\x00\x00\x00\x00\x00\x00\x00"

        return pkt_data

    def get_pkt1(self):
        return self.get_pkt_data(self.pkt_id, 1, self.per_1000_setp, self.some_flux, 
            "\x00\x00\x00\x00")

    def get_pkt3(self):
        return self.get_pkt_data(self.pkt_id, 3, self.per_1000_setp, self.some_flux, 
            socket.inet_aton(self.client_ip))

    def run(self):
        # 第一个包不加一
        self.send_pkt1(False)
        while True:
            print("i am while")
            recv_data = self.client.recv(1600)
            r_id = self.deal_recv(recv_data)
            print("i am back")
        pass




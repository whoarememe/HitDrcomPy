#coding:utf-8

import threading
import socket
import hashlib
from utils import *
import time
from struct import *
from config import *

UDP_ALIVE_CODE = "\xff"
CODE_MISC = 0x07
AUTH_TYPE = 0x0800
STEP_TYPE = 0x2800

LOCK = threading.RLock()

# 开始认证
# eap认证成功之后首先进行的是这个认证，成功之后分两个线程进行心跳，
# 否则重新链路层认证,我觉得这个东西没用
class udp_auth_stu_dist():
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
        LOCK.acquire()
        self.client.send(pkt_data)
        recv_data = self.client.recv(1600)
        LOCK.release()

        # 返回1认证成功，其他认证失败，重新发送此包
        return self.deal_recv(recv_data)
        pass

# 20s定时心跳，暂时没有搞定，没有找到加密方式
class udp_alive(threading.Thread):
    def __init__(self, nic_info, udp_client, udp_auth):
        threading.Thread.__init__(self)
        self.client_ip = nic_info.get_local_ip()
        self.server_ip = nic_info.get_server_ip()
        self.client = udp_client
        self.md5a = udp_auth.get_md5a()
        self.auth_info = udp_auth.get_auth_info()
        print("len in alive " + str(len(self.md5a)))

    def get_auth_info(self):
        # Drco + serverIp
        return self.auth_info
        #  return "Drco" + \
            #  socket.inet_aton(self.server_ip) + \
            #  "\x00\x00" + \
            #  socket.inet_aton(self.client_ip) + \
            #  "\x00\x00"

    def get_time(self):
        return pack("H", int(time.time() % 86400))

    def get_md5_info(self):
        b = bytearray()
        b += "\x03\x01" + self.challenge + CON_PASSWORD

        m2 = hashlib.md5()
        m2.update(b)

        return m2.digest()

    def get_alive_pkt(self):
        return UDP_ALIVE_CODE + self.md5a + \
            3*"\x00" + self.get_auth_info() + "\x00\x00"
            # self.get_time()

    def deal_recv(self, recv_data):
        code = recv_data[0]

        print("deal per 20")
        if code == 0x07:
            print("per 20 success!!")
        else:
            print("failure!!")

    def run(self):
        while True:
            color_print.info("send alive per 20!")
            #  LOCK.acquire()
            self.client.send(self.get_alive_pkt())
            try:
                rec_data = self.client.recv(1600)
                self.deal_recv(rec_data)
            except socket.timeout:
                pass
            #  LOCK.release()
            time.sleep(20)

# 四步心跳
class alive_step(threading.Thread):
    def __init__(self, udp_alive, nic_info, auth):
        threading.Thread.__init__(self)
        self.auth = auth
        self.client = udp_alive
        self.pkt_id = 0
        self.per_1000_setp = "\x00\x00"
        self.some_flux = "\x00\x00\x00\x00"
        self.first_pkt = True
        # 使用字符串
        self.client_ip = nic_info.get_local_ip()
        # 重发将发送第几个包
        self.__current = 1
        self.__start = True
        # 接收包超时计数
        self.__timeout_count = 0
        # error pkt
        self.__error_pkt = 0

    # def start_thread(self):
    #     self.__start = True

    # source big
    # def get_timeout_count(self):
    #     return self.__timeout_count

    def stop(self):
        color_print.info("暂停")
        self.__start = False

    def restart(self):
        color_print.info("重启")
        self.__timeout_count = 0
        self.__error_pkt = 0
        self.__current = 1
        self.pkt_id = 0
        self.per_1000_setp = "\x00\x00"
        self.some_flux = "\x00\x00\x00\x00"
        self.first_pkt = True
        self.__start = True
        self.send_pkt1(False)
        pass

    def send_pkt1(self, add_one):
        self.__current = 1
        if add_one:
            if self.pkt_id >= 255:
                self.pkt_id = 0
            else:
                self.pkt_id += 1

        pkt_data = self.get_pkt1()

        color_print.info("发送1号心跳包 " + str(self.pkt_id))
        LOCK.acquire()
        self.client.send(pkt_data)
        LOCK.release()

        self.first_pkt = False

    def send_pkt3(self, add_one):
        self.__current = 3
        if add_one:
            if self.pkt_id >= 255:
                self.pkt_id = 0
            else:
                self.pkt_id += 1

        pkt_data = self.get_pkt3()
        color_print.info("发送3号心跳包 " + str(self.pkt_id))
        LOCK.acquire()
        self.client.send(pkt_data)
        LOCK.release()

    # 处理接收并发送
    def deal_recv(self, recv_data):

        code_misc, pkt_id, pkt_type, fix1, pkt_step  = unpack("!BBHBB", recv_data[0:6])

        if code_misc == CODE_MISC and pkt_type == STEP_TYPE:
            # 判断当前包的id与收到的id是否一样，不一样重新发送第一个包，都重新发送一号包吧
            #  or self.pkt_id == pkt_id + 1 or self.pkt_id == pkt_id - 1
            if self.pkt_id == pkt_id:
                color_print.info("set flux")
                self.some_flux = recv_data[16:20]
                # 第二步
                if pkt_step == 0x02:
                    color_print.info("收到2号包 " + str(pkt_id))

                    # self.__current = 3
                    self.__timeout_count = 0
                    self.send_pkt3(True)

                    return 3
                # 第四步，如果到了第四步，那么睡眠20s，然后发送
                elif pkt_step == 0x04:
                    color_print.info("收到4号包 " + str(pkt_id))
                    color_print.ok("延迟20s")
                    time.sleep(20)
                    color_print.ok("延迟结束，重新发送1号包")

                    # self.__current = 1
                    self.__timeout_count = 0
                    self.send_pkt1(True)

                    return 4
                else:
                    # self.__current = 1
                    self.send_pkt1(False)
                    return -1
            else:
                color_print.warning("pkt id不匹配，返回等待， 收到的pkt id是： " + str(pkt_id))
                # self.__error_pkt += 1
                # if self.__error_pkt > 2:
                #     print("重新设置了pkt id！")
                #     self.pkt_id = pkt_id
                #     self.__error_pkt = 0
                # self.pkt_id = pkt_id
                # 如果id不匹配的话，重新发送，不知道这里的pktid要不要+1，暂时不加1了吧
                # time.sleep(2)
                # 这个要不要注释掉，如果三号包不匹配，那么一直发送三号包么？？重新发送三号包
                # self.__current = 1
                # self.send_pkt(False)
                return

        # pktid匹配，但不是四步中的话重新发送当前包，pkt_id自动加1的，重发的加1
        elif self.pkt_id == pkt_id:
            color_print.warning("重新发送pkt！！")
            # if self.__error_pkt > 3:
            #     pass
            # self.__error_pkt += 1
            # time.sleep(2)
            # self.__current = 1
            # time.sleep(2)
            # self.send_pkt(True)
            return
        else:
            time.sleep(2)
            self.send_pkt1(False)
            return

    # int, int, "\x00\x00", "\x00\x00\x00\x00"
    def get_pkt_data(self, pkt_id, step_id, per_1000_setp, some_flux, client_ip):

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

    def send_pkt(self, t_or_f):
        if self.__current == 1:
            self.send_pkt1(t_or_f)
        elif self.__current == 3:
            self.send_pkt3(t_or_f)

    def run(self):
        self.send_pkt1(False)
        # self.client.send("hello")
        while True:
            # if self.__start:
            try:
                LOCK.acquire()
                recv_data = self.client.recv(1600)
                LOCK.release()
            except socket.timeout:
                    # 重新发送，现在是不管第一个还是第三个包，没有收到响应都要将pkt+1
                color_print.warning("接收包超时，重新发送" + str(self.__current) + "号包！")
                if self.__timeout_count < 2:
                    self.send_pkt(True)
                    self.__timeout_count += 1
                else:
                    self.auth.logoff()
                    self.auth.start_auth()
                    self.restart()

                continue
            r_id = self.deal_recv(recv_data)
            # else:
            #     print("not start!!")
            #     continue
        pass

#coding:utf-8

'''
教学区udp认证
'''
import hashlib
import socket
import struct
from utils import *
from udp_alive import *
import time

CHALLENGE = ""

class udp_auth():
    __success = False

    def __init__(self, udp_client, u_name, u_password, nic_info):
        self.client = udp_client
        self.user_name = bytearray()
        for i in range(0, len(u_name)):
            self.user_name.append(ord(u_name[i]))
        self.user_password = bytearray()
        for i in range(0, len(u_password)):
            self.user_password.append(ord(u_password[i]))
        self.mac = nic_info.get_local_mac()
        self.ip_addr = nic_info.get_local_ip()
        self.md5a = ""
        self.header = ""
        self.auth_info = ""
        self.timeout_count = 0
        pass

    def get_md5a(self):
        return self.md5a

    # 是否登录成功
    def if_success(self):
        return self.__success

    #
    def set_header(self, code, challenge):
        c_type = "\x01"
        eof = "\x00"
        u_len = chr(20 + (36 if len(self.user_name) > 36 else len(self.user_name)))
        MD5A = self.get_md5a_info(code, c_type, challenge, self.user_password)
        self.md5a = MD5A
        color_print.info("MD5A length %x"%(len(self.md5a)))
        u_name = self.get_u_name(self.user_name)
        fixed_unknow = "\x20"
        mac_flag = "\x01"
        # mac异或MD5a
        mac_xor_md5a = self.get_xor_info(self.mac, MD5A)

        self.header = c_type + eof + u_len + MD5A + u_name + fixed_unknow + \
                mac_flag + mac_xor_md5a

    # 第一个请求包
    def get_start_pkt(self):
        return "\x01" + "\x00" + "\x00\x00" + "\x00" + 15*"\x00"

    # 第二个认证包
    def get_auth_pkt(self, challenge):
        code = "\x03"
        #  self.set_header(code, challenge)
        c_type = "\x01"
        eof = "\x00"
        u_len = chr(20 + (36 if len(self.user_name) > 36 else len(self.user_name)))
        MD5A = self.get_md5a_info(code, c_type, challenge, self.user_password)
        self.md5a = MD5A
        color_print.info("MD5A length %x"%(len(self.md5a)))
        u_name = self.get_u_name(self.user_name)
        fixed_unknow = "\x20"
        mac_flag = "\x01"
        # mac异或MD5a
        mac_xor_md5a = self.get_xor_info(self.mac, MD5A)
        self.header = c_type + eof + u_len + MD5A + u_name + fixed_unknow + \
                mac_flag + mac_xor_md5a

        MD5B = self.get_md5b_info(self.user_password, challenge)
        nic_count = "\x01"
        nic_ips = socket.inet_aton(self.ip_addr) + 12 * "\x00"
        checksum = self.get_check_info(code + c_type + eof + u_len + MD5A + u_name \
            + fixed_unknow + mac_flag + mac_xor_md5a + MD5B + nic_count + nic_ips + \
            "\x14\x00\x07\x0b")
        checksum_1 = checksum[0:8]
        ip_dog = "\x01"
        zeros1 = 4*"\x00"
        # h_name = lambda x : socket.gethostname()[0:32] if x > 32 else socket.gethostname()
        host_name = self.get_h_name()
        # 主副dns，暂时以0填充
        pri_dns = 4 * "\x00"
        dhc_server = 4 * "\x00"
        sec_dns = 4 * "\x00"
        zeros2 = 8 * "\x00"
        unknow1 = 4 * "\x00"
        os_major = 4 * "\x00"
        os_minor = 4 * "\x00"
        os_builder = 4 * "\x00"
        # 不知道这个用0可不可以
        unknow2 = "\x00\x00\x00\x01"
        ker_ver = "DrCOM" + 27 * "\x88"
        zeros3 = 96 * "\x00"
        checksum_2 = "\x0a\x00\x02\x0c" + checksum[10:14]
        unknow3 = "\x00\x00"
        mac_addr = self.mac
        # false
        auto_logout = "\x00"
        br_mode = "\x00"
        unknow4 = "\x00\x00"

        return code + self.header + MD5B + nic_count + nic_ips + checksum_1 +\
            ip_dog + zeros1 + host_name + pri_dns + dhc_server + sec_dns +\
            zeros2 + unknow1 + os_major + os_minor + os_builder + unknow2 +\
            ker_ver + zeros3 + checksum_2 + unknow3 + mac_addr + auto_logout +\
            br_mode + unknow4

    # md5a
    def get_md5a_info(self, code, c_type, challenge, password):
        b_data = bytearray()

        b_data.append(code)
        b_data.append(c_type)

        for i in range(0, len(challenge)):
            b_data.append(challenge[i])
        b_data += password

        m2 = hashlib.md5()
        m2.update(b_data)

        return m2.digest()

    # username
    def get_u_name(self, name):
        b = bytearray()
        if len(name) > 36:
            b = name[0:32]
        else:
            b += name
            b += (36-len(name)) * "\x00"

        return b

    # ^
    def get_xor_info(self, mac, md5a):
        r_data = bytearray()

        for i in range(0, len(mac)):
            r_data.append(chr(ord(mac[i]) ^ ord(md5a[i])))

        return r_data

    # 01 password challenge 4*00
    def get_md5b_info(self, password, challenge):
        b = bytearray()
        b.append("\x01")

        b += password

        for i in range(0, len(challenge)):
            b.append(challenge[i])

        b += 4 * "\x00"

        m2 = hashlib.md5()
        m2.update(b)

        return m2.digest()

    # checksum
    def get_check_info(self, info):
        m2 = hashlib.md5()
        m2.update(info)

        return m2.digest()

    #
    def get_h_name(self):
        b = bytearray()
        h_name = socket.gethostname()

        if len(h_name) > 32:
            return h_name[0:32]
        else:
            return h_name + (32 - len(h_name)) * "\x00"

    def set_auth_info(self, server, client):
        self.auth_info = "Drco" + server + "\x00\x00" + client + "\x00\x00"

    # 处理接收的包
    def deal_recv(self, recv_data):
        code, = struct.unpack("!B", recv_data[0:1])

        if code == 0x02:
            color_print.info("return code %x, need info back"%(code))
            challenge = recv_data[4:8]
            client_ip = recv_data[20:24]
            if client_ip == socket.inet_aton(self.ip_addr):
                color_print.info("Ip 地址正确")
                color_print.info("准备发送第二次认证")
                self.client.send(self.get_auth_pkt(challenge))
        elif code == 0x04:
            color_print.info("return code %x, log success"%(code))
            if not recv_data[1:]:
                return True
            used_month = recv_data[5:9]
            used_flux = recv_data[9:13]
            balance = recv_data[13:17]
            server_ip = recv_data[27:31]
            client_ip = recv_data[33:37]
            self.auth_info = recv_data[23:41]
            color_print.info("\n服务器ip: %s\n客户端ip: %s\n余额: \
                    %s"%(socket.inet_ntoa(server_ip), \
                        socket.inet_ntoa(client_ip), \
                        balance))
            return True
        else:
            color_print.info("return code %x, log failure"%(code))
            return False


    def start_auth(self):
        color_print.info("准备登录请求")
        self.client.send(self.get_start_pkt())
        color_print.info("登录请求发送成功")
        while True:
            color_print.info("准备接收登录返回数据")
            try:
                recv_data = self.client.recv(1600)
                color_print.info("准备处理接收数据")
                if self.deal_recv(recv_data):
                    break
            except socket.timeout:
                self.timeout_count += 1
                if self.timeout_count > 5:
                    self.logoff()
                    self.client.send(self.get_start_pkt())
                pass

        return True

    def get_auth_info(self):
        return self.auth_info

    def get_logoff_pkt(self):
        code = "\x06"
        return code + self.header + self.auth_info

    def logoff(self):
        color_print.info("logoff")
        self.client.send(self.get_logoff_pkt())
        try:
            recv_data = self.client.recv(1600)
            if self.deal_recv(recv_data[0:1]):
                color_print.info("logoff success")
                return True
        except socket.timeout:
            pass

#  if __name__ == "__main__":
    #  #u = nic_info("wlp3s0")
    #  #c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #  #c.bind((u.get_local_ip(), u.get_local_port()))
    #  #c.connect((u.get_server_ip(), u.get_server_port()))
    #  #a = udp_auth(c, "o140730205", "19951222", u)
    #  if a.start_auth():
    #      # time.sleep(2)
    #      print("main len: " + str(len(a.get_md5a())))
    #      alive20 = udp_alive(u, c, a.get_md5a())
    #      setp4 = alive_step(c, u, a)
    #
    #      alive20.setDaemon(True)
    #      setp4.setDaemon(True)
    #      alive20.start()
    #      time.sleep(2)
    #      setp4.start()
    #
    #  while True:
    #      time.sleep(10)
        #  pass

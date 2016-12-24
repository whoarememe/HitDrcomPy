from utils import get_ip_address

CON_ACCOUNT = "用户名"

CON_PASSWORD = "密码"

CON_IFNAME = "网卡名称"

# 一般不需要设置，设置的话一定要与你的网卡ip相同
CON_LOCAL_IP = ""

###############################
SERVER_ADDR = "172.25.8.4"
SERVER_PORT = 61440
LOCAL_PORT = 61440
if CON_LOCAL_IP:
    LOCAL_IP = CON_LOCAL_IP
else:
    LOCAL_IP = get_ip_address(CON_IFNAME)


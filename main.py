from eap_dealer import *
from udp_alive import *
from config import *
import socket

if __name__ == "__main__":
    # while True:
    #     pass
    b = eap_dealer("141110320", "19950505", "enp4s0f1")
    if b.start_auth():
        print "i am here"
        print LOCAL_IP
        udp_alive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_alive.bind((LOCAL_IP, LOCAL_PORT))
        udp_alive.connect((SERVER_ADDR, SERVER_PORT))
        a = alive_step(udp_alive)
        a.run()
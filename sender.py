# Ortal Lankri, 209281674, Adi Meirman, 208177204
import random
import sys
import base64
import os
import socket
import threading
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

m_list = []
global round_num
round_num = 0


def manage():
    time.sleep(5)
    copy = m_list.copy()
    send_messages(copy)
    global round_num
    round_num += 1
    manage()


def send_messages(messages_list):
    for m in messages_list:
        if m[3] == round_num:
            send_message(m[0], m[1], m[2])


def send_message(message, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    # print("connected")
    s.send(message)
    print("sent")
    s.close()


def encrypt(message):
    # make key
    password = message[3].encode()
    salt = message[4].encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    # get ip and port of destination
    ip = bytes(map(int, message[5].split('.')))
    port = (int(message[6])).to_bytes(2, 'big')
    # encrypt the message
    token = f.encrypt(message[0].encode())
    msg = ip + port + token
    # print(msg)
    # encrypt the message for the mix-servers
    ips = open("ips.txt").read().split("\n")
    path = message[1].split(",")
    path.reverse()
    i = 0
    for num in path:
        fileName = "pk" + num + ".pem"
        publicKey = open(fileName).read()
        pemKey = load_pem_public_key(publicKey.encode())
        if i > 0:
            # get ip and port of previous mix-server
            previous = int(path[i-1])
            data = ips[previous - 1].split(" ")
            ip = bytes(map(int, data[0].split('.')))
            port = (int(data[1])).to_bytes(2, 'big')
            msg = ip + port + msg
        # encrypt message
        msg = pemKey.encrypt(msg, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        i += 1
        # print(msg)
    # send message
    path.reverse()
    num = path[0]
    data = ips[int(num) - 1].split(" ")
    m_list.append([msg, data[0], int(data[1]), int(message[2])])


def main():
    t = threading.Thread(target=manage)
    t.start()
    x = str(sys.argv[1])
    fileName = "messages" + x + ".txt"
    file = open(fileName).read()
    messages = file.split("\n")
    # encrypt(messages[0].split(" "))
    for message in messages:
        if message != "":
            encrypt(message.split(" "))


if __name__ == "__main__":
    main()


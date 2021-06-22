# Ortal Lankri, 209281674, Adi Meirman, 208177204

import sys
import base64
import os
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def send_message(message, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("connected")
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
    # ip = str(ip)[2:len(str(ip))-1]
    port = (int(message[6])).to_bytes(2, 'big')
    # port = str(port)[2:len(str(port))-1]
    # encrypt the message
    token = f.encrypt(message[0].encode())
    # send_message(f.encrypt(message[0].encode()), "127.0.0.1", int("5000"))
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
        # msg = base64.b64encode(msg).decode()
        # msg = msg.decode()
        # msg = msg[2:len(msg)-1]
        i += 1
        print(msg)
    # send message
    path.reverse()
    num = path[0]
    data = ips[int(num) - 1].split(" ")
    send_message(msg, data[0], int(data[1]))


def main():
    x = str(sys.argv[1])
    fileName = "messages" + x + ".txt"
    file = open(fileName).read()
    messages = file.split("\n")
    encrypt(messages[0].split(" "))
    # for message in messages:
    #     encrypt(message.split(" "))


if __name__ == "__main__":
    main()


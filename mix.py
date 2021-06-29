# Ortal Lankri, 209281674, Adi Meirman, 208177204

import random
import socket
import sys
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

m_list = []


def manage():
    threading.Timer(60, manage).start()
    copy = m_list.copy()
    m_list.clear()
    send_messages(copy)


def send_messages(messages_list):
    random.shuffle(messages_list)
    for m in messages_list:
        send_message(m[0], m[1], m[2])


def send_message(message, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(message)
    s.close()


def decrypt(message, num):
    fileName = "sk" + num + ".pem"
    privateKey = open(fileName).read()
    pemKey = load_pem_private_key(privateKey.encode(), password=None)
    msg = pemKey.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # decrypt ip and port
    s = msg[0:4]
    ip = str(s[0]) + "." + str(s[1]) + "." + str(s[2]) + "." + str(s[3])
    s = msg[4:6]
    port = int.from_bytes(s, 'big')
    msg = msg[6:]
    # add message to list
    m_list.append([msg, ip, int(port)])


def main():
    threading.Timer(60, manage).start()
    num = sys.argv[1]
    ips = open("ips.txt").read().split("\n")
    data = ips[int(num) - 1].split(" ")
    port = int(data[1])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', port))
    server.listen(10)
    while True:
        client_socket, client_address = server.accept()
        data = client_socket.recv(4096)
        decrypt(data, num)
        client_socket.close()


if __name__ == "__main__":
    main()

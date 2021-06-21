# Ortal Lankri, 209281674, Adi Meirman, 208177204
import base64
import binascii
import socket
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def send_message(message, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("connected")
    s.send(message)
    print("sent")
    s.close()


def decrypt(message, num):
    fileName = "sk" + num + ".pem"
    privateKey = open(fileName).read()
    pemKey = load_pem_private_key(privateKey.encode(), password=None)
    print(len(message))
    print(len(privateKey))
    print(len(pemKey))
    msg = pemKey.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    msg = base64.decodebytes(msg)
    s = str(msg)[0:4]
    ip = str(ord(s[0])) + "." + str(ord(s[1])) + "." + str(ord(s[2])) + "." + str(ord(s[3]))
    print(ip)
    s = str(msg)[4:6]
    port = ord(s[0]) * 256 + ord(s[1])
    print(port)
    msg = str(msg)[6:]
    send_message(msg, ip, int(port))


def main():
    num = sys.argv[1]
    ips = open("ips.txt").read().split("\n")
    data = ips[int(num) - 1].split(" ")
    port = int(data[1])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', port))
    server.listen(5)
    while True:
        client_socket, client_address = server.accept()
        print("connected")
        data = client_socket.recv(4096)
        decrypt(data, num)
        client_socket.close()


if __name__ == "__main__":
    main()

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
    # message = base64.decodebytes(message)
    msg = pemKey.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    s = msg[0:4]
    ip = str(s[0]) + "." + str(s[1]) + "." + str(s[2]) + "." + str(s[3])
    print(ip)
    s = msg[4:6]
    port = int.from_bytes(s, 'big')
    print(port)
    msg = msg[6:]
    send_message(msg, ip, int(port))


def main():
    # msg = "\\x7f\\x00\\x00\\x01\\x13\\x88gAAAAABg0axKRa6jzUo8gRsEyE1SHspbDUNij7U6H6p_875RW29FJ2fEmQ95UpWDVOK8qxT9cFxJqP5I1gWoHB4m3c9GzJRL2A=="
    # print(msg[0])
    # msg = ascii(msg)
    # msg = msg.replace('\\\\', '\\')
    # print(msg)
    # msg = msg.strip('\'')
    # print(msg)
    # s = msg[0:4]
    # print(s)
    # ip = str(ord(s[0])) + "." + str(ord(s[1])) + "." + str(ord(s[2])) + "." + str(ord(s[3]))
    # print(ip)
    # s = str(msg)[4:6]
    # port = ord(s[0]) * 256 + ord(s[1])
    # print(port)

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

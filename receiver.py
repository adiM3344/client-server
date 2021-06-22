# Ortal Lankri, 209281674, Adi Meirman, 208177204
import socket
import sys
from datetime import datetime
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def decrypt(message, password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    return f.decrypt(message).decode()


def main():
    port = int(sys.argv[3])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', port))
    server.listen(10)
    while True:
        client_socket, client_address = server.accept()
        # print("connected")
        data = client_socket.recv(4096)
        data = decrypt(data, sys.argv[1].encode(), sys.argv[2].encode())
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print(data + " " + current_time)
        client_socket.close()


if __name__ == "__main__":
    main()

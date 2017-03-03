

import socket
import argparse

import random, struct
from RSA import rsaGenerate
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
import re

#Encrypt function of CBS
def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):

    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))


class Client(object):
    def __init__(self, password, filename, servername, port, client_private_key,client_public_key, server_public_key):

        self.password = password
        self.filename = filename
        self.servername = servername
        self.port = port
        self.client_private_key = client_private_key
        self.client_public_key = client_public_key
        self.server_public_key = server_public_key
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serveraddress = (self.servername, self.port)
        try:
            self.s.connect(serveraddress)
        except socket.error as error:
            print ("Connection failed", error)
        self.encrypt_file()
        self.send_data()
        self.rsa()
        self.sign()

    def encrypt_file(self): # Encrypts the input file and creates an output file "filename.enc"
         encrypt_file(self.password, self.filename)

    def send_data(self): #Sends the encrypted file to the server in 1024 chunk
        fenc = self.filename + ".enc"

        with open(fenc) as infile:
            d = infile.read(1024)
            while d:
                self.s.sendall(d)
                d = infile.read(1024)
            print "Send successfully"
            self.s.close()
            self.sendsign()

    def sendsign(self):

        self.s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s1.connect((self.servername, self.port))
        key = self.encryptkey()
        self.s1.sendall(key)
        signature = self.sign()
        self.s1.sendall(signature)
        self.s1.close()

    def encryptkey(self):
        key = RSA.importKey(open(self.server_public_key).read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(self.password)
        return ciphertext

    def rsa(self):
        rsaGenerate('client')

    #Signs the SHA256 hash of the file contents with client's private key.
    def sign(self):

        with open(self.filename) as file:
            message = file.read()
        key = RSA.importKey(open(self.client_private_key).read())
        h = SHA256.new()
        h.update(message)
        signer = PKCS1_PSS.new(key)
        signature = signer.sign(h)
        return signature


def integrity_check(password, filename, servername, port, client_private_key, client_public_key,server_public_key):

    if len(password) != 16:
        print "Password should be 16 in length"
        return False
    elif not re.match("^[a-zA-Z0-9_]*$", password):
        print "Password should only contain legal characters"
        return False
    elif (port < 1024 or port > 65536):
        print "Port Number out of range"
        return False
    elif not (os.path.isfile('fakefile')):
        print "Missing file."
        return False
    elif not (os.path.isfile(client_private_key) and os.path.isfile(client_public_key)
            and os.path.isfile(server_public_key)):
        print "The .pem files should be in the same folder as this."
        return False

    else:
        return True


def main():


    parser = argparse.ArgumentParser(description="Client")
    parser.add_argument("password", type=str)
    parser.add_argument("filename", type=str)
    parser.add_argument("servername", type=str)# here local host
    parser.add_argument("port", type=int)
    parser.add_argument("client_private_key", type=str)
    parser.add_argument("client_public_key", type=str)
    parser.add_argument("server_public_key", type=str)
    args = parser.parse_args()
    if integrity_check(args.password, args.filename, args.servername, args.port,
                    args.client_private_key, args.client_public_key, args.server_public_key):
        server = Client(args.password, args.filename, args.servername, args.port,
                        args.client_private_key, args.client_public_key, args.server_public_key)
    else:
        exit(0)


if __name__ == "__main__":
    main()

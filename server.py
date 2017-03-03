

import struct
import argparse
import socket
import os
from RSA import rsaGenerate
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256


####Decrypts a file using CBC mode and produce a outfile
def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while 1:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)


#server class with basic function
class Server(object):


    def __init__(self, port, mode, server_private_key, server_public_key, client_public_key):

        self.host = "localhost"
        self.port = port
        self.mode = mode
        self.server_private_key = server_private_key
        self.server_public_key = server_public_key
        self.client_public_key = client_public_key
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serversocket.bind((self.host, self.port))
        except socket.error as error:
            print ("Binding error: ", error)
            exit()

        # only one client can connect
        count = 0
        while True:
            serversocket.listen(1)
            if count == 0:
                count += 1
                rsaGenerate('server')  # Generate the RSA Keys(if not exists)
                (clientsocket, clientaddress) = serversocket.accept()
                self.receive(clientsocket)
            elif count == 1:
                self.normal_listen(serversocket)
                break

    def normal_listen(self, serversocket):
        (clientsocket, clientaddress) = serversocket.accept()
        self.normal_recv(clientsocket)
        clientsocket.close()


    def normal_recv(self, clientsocket):
        """
        Designed to Recieve Key Used for Encryption and Signature Verification.
        Has 2 Socket.recv calls.
        """
        data = clientsocket.recv(1024)
        signature = clientsocket.recv(1024)
        key = RSA.importKey(open(self.server_private_key).read())
        cipher = PKCS1_OAEP.new(key)
        AES_KEY = cipher.decrypt(data)  # AES_KEY using Server's Private Key.
        self.decrypt(AES_KEY)
        self.verify_signature(signature)




   # Recieves AES_CBC mode encrypted file from the Socket and writes in file decrypted.enc
    def receive(self, clientsocket):
        data = ""
        while True:
            buffer = clientsocket.recv(1024)
            data += buffer
            if not buffer:
                break
        with open('decrypted.enc', 'wb')as dec:
            dec.write(data)
        clientsocket.close()



    ##verify the hashed signature

    def verify_signature(self, signature):

        key = RSA.importKey(open(self.client_public_key).read())
        hashh = SHA256.new()
        if self.mode == 't':
            recvddata = open('decrypted').read()
        elif self.mode == "u":
            recvddata = open('fakefile').read()
        hashh.update(recvddata)
        verifier = PKCS1_PSS.new(key)

        if not verifier.verify(hashh, signature):
            print "Verification Failed"
        else:
            print "Verification Passed"




    def decrypt(self, AES_KEY):
        decrypt_file(AES_KEY, 'decrypted.enc')


def integrity_check(port, mode, server_private_key, server_public_key, client_public_key):

    if (port < 1024 or port > 65536):
        print "Port Number should only be in [1024,65536]"
        return False
    elif not (mode != 't' or mode != 'u'):
        print "Mode can only be untrusted(u) or trusted(t)"
        return False
    elif not (os.path.isfile(server_public_key) and os.path.isfile(server_private_key)):
        print "Key pair should be in this exact folder"
        return False
    elif (server_public_key == server_private_key):
        print "Key pair should be different"
        return False
    else:
        return True

#driver function in server
def main():

    parser = argparse.ArgumentParser(description="Server" )
    parser.add_argument("port", type=int)
    parser.add_argument("mode", type=str)
    parser.add_argument("server_private_key", type=str)
    parser.add_argument("server_public_key", type=str)
    parser.add_argument("client_public_key", type=str)
    args = parser.parse_args()
    try:
        if integrity_check(args.port, args.mode, args.server_private_key, args.server_public_key, args.client_public_key):
            server = Server(args.port,args.mode,args.server_private_key,args.server_public_key,args.client_public_key)

        else:
            print "Server parameters wrong "
            exit()
    except KeyboardInterrupt:
        print "Successfully quit "
        exit()


if __name__ == "__main__":
    main()

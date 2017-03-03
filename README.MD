User Guide for  COMS4180   hw1  Jianpu Ma jm4437

Implement Steps

1,make sure your VM has the Python version 2.7 and has installed python pycrypto package, if not, type:
$ pip install pycrypto

2,for generating the RSA key type if there are not such files in the folder, type:
$ python 
>>> from RSA import rsaGenerate
>>> rsaGenerate('client')
>>> rsaGenerate('server')

3, for running the server, there are 2 mode in sever as trusted and untrusted,other parameters include port, mode, private server key, public server key and client public key, set up by typing：
$ python server.py + Port  + Mode + server_private.pem + server_public.pem+ client_public.pem
for example:
$ python server.py 8080 t server_private.pem server_public.pem client_public.pem  (in trusted mode )
or
$ python server.py 8080 u server_private.pem server_public.pem client_public.pem  (in untrusted mode )

4, running  the client, by typing:
$ python client.py + password + Filename + Server Name + Port Number + Client Private Key file + Client Public Key file +Server Public Key file
for example:
$ python client.py abcdefghijklmnop 'The Canterbury Tales.txt' localhost 8080 client_private.pem client_public.pem server_public.pem

5, You will see the Verification status on the terminal window, and the client and server will automatically exit after verified



There is a file named RSA.py which is the generator for the RSA key pair, the main generating function is the RSA from Crypto.PublicKey.
We use RSA.generate(2048) and so on to get a 2048 bit key and write into the PEM and store it.


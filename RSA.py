
####### This  file is for RSA KEY generating, only generate when there are not such file in the folder #################
####### It generates two files as : 'mode_public.pem' and 'mode_private.pem'
import sys
import os
from Crypto.PublicKey import RSA

if len(sys.argv) >1 :
   mode = sys.argv[1]

def rsaGenerate(mode):

    privatename = mode + "_private.pem"
    publicname = mode + "_public.pem"

    if os.path.isfile(publicname):
        print "Using current RSA file"
        return
    private_key = RSA.generate(2048)
    publickey = private_key.publickey()


    f = open(privatename, 'w')
    f.write(private_key.exportKey('PEM'))
    f1 = open(publicname, 'w')
    f1.write(publickey.exportKey('PEM'))
    print mode + " RSA key generated"



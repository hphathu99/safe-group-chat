from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import genkey
import session
import os

NETPATH = './network'
outputfile = 'message.bin' # default output
inputfile  = None
sessionkeyfile = None
ssidfile = None
sqnfile = None

def enc_invite(addresses):
    dst = list(addresses)
    # compute message length...
    # header: 5 bytes
    #    version: 2 bytes [1:3]
    #    type:    1 byte [0:1]
    #        invite: 1, message: 2, shut down session: 3
    #    length:  2 bytes [3:5]
    # admin's id: 1 bytes [5:6]
    # n: 2 bytes [6:8]
    # p1's id: 1 byte [8:9]
    # p1's content: RSA pub key scheme
    # p1's id: 8 bytes
    # p1's content: RSA pub key scheme
    # signature: 256 bits - 256 bytes RSA signature scheme
    msg_length = 5 + 1 + 2 + len(dst)*(1+256) + 32

    # create header
    header_type = b'\x01'                                   # message type 1
    header_version = b'\x03\x06'                            # protocol version 3.6
    header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
    header = header_type + header_version + header_length 

    # create admin's id and number of participants
    admin_id = b'A'
    n = len(dst).to_bytes(2, byteorder='big')
    admin_info = admin_id + n 

    # create encryption key for all participants
    session_key = get_random_bytes(16)
    sessionkeyfile = NETPATH + '/' + 'A' + '/' +'sskey.pem'
    sskey = session_key
    with open(sessionkeyfile, 'wb') as sskf:
        sskf.write(sskey)
    state = 'sndsqn: ' + '0'*(len(dst)+1) +'\n'
    state += 'rcvsqn: ' + '0'*(len(dst)+1) + '\n'
    sqnfile = NETPATH + '/' + 'A' + '/' +'sqn.txt'
    with open(sqnfile, 'wt') as tf:
        tf.write(state)
    enc = b''
    for des in dst:
        des_id = des.encode()
        pubkeyfile = NETPATH + '/' + des + '/' + 'pubkey.pem'
        pubkey = genkey.load_publickey(pubkeyfile)
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        enc_key = cipher_rsa.encrypt(session_key)
        enc += des_id + enc_key
    content = header + admin_info + enc
    keypair = genkey.load_keypair(NETPATH + '/' + 'A' + '/' +'privkey.pem')
    signer = pss.new(keypair)
    hashfn = SHA256.new()
    hashfn.update(content)
    signature = signer.sign(hashfn)
    content += signature

    ssidfile = NETPATH + '/' + 'A' + '/' + 'ssid.pem'
    ssf = open(ssidfile, 'wt')
    h = SHA256.new(content)
    ssf.write(h.hexdigest())
    return content

    # write out the header, iv, encrypted payload, and the mac
    with open(outputfile, 'wb') as outf:
        outf.write(header + content)

def enc_accept(src, ssid):
    # compute message length...
    # header: 5 bytes
    #    type:    1 byte [0:1]
    #        invite: 1, accept: 2
    #    version: 2 bytes [1:3]
    #    length:  2 bytes [3:5]
    # user's id: 1 bytes [5:6]
    # hash invite: 64 bytes
    # signature: 256 bytes RSA signature scheme
    msg_length = 5 + 1 + 64 + 256

    # create header
    header_type = b'\x02'                                   # message type 1
    header_version = b'\x03\x06'                            # protocol version 3.6
    header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
    header = header_type + header_version + header_length 

    # create admin's id and number of participants
    user_id = src.encode()
    ssid = ssid.encode()
    content = header + user_id + ssid
    keypair = genkey.load_keypair(NETPATH + '/' + src + '/' +'privkey.pem')
    signer = pss.new(keypair)
    hashfn = SHA256.new()
    hashfn.update(content)
    signature = signer.sign(hashfn)
    content += signature

    return content

def enc_destroy(src, ssid):
    # compute message length...
    # header: 5 bytes
    #    type:    1 byte [0:1]
    #        invite: 1, accept: 2
    #    version: 2 bytes [1:3]
    #    length:  2 bytes [3:5]
    # user's id: 1 bytes [5:6]
    # hash invite: 64 bytes
    # signature: 256 bytes RSA signature scheme
    msg_length = 5 + 1 + 256

    # create header
    header_type = b'\x04'                                   # message type 1
    header_version = b'\x03\x06'                            # protocol version 3.6
    header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
    header = header_type + header_version + header_length 

    # create admin's id and number of participants
    user_id = src.encode()
    content = header + user_id 
    keypair = genkey.load_keypair(NETPATH + '/' + src + '/' +'privkey.pem')
    signer = pss.new(keypair)
    hashfn = SHA256.new()
    hashfn.update(content)
    signature = signer.sign(hashfn)
    content += signature

    return content
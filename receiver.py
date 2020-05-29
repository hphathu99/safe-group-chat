#!/usr/bin/env python3
#receiver.py
import genkey
import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import message

NET_PATH = './'
OWN_ADDR = 'B'
KEYGEN = False
VERIFIED = False
sessionkeyfile = None
ssidfile = None
sqnfile = None

def dec_msg(msg):
	msg_type = msg[0:1]
	if msg_type == b'\x01':
		dec_invite(msg)
	elif msg_type == b'\x02':
		dec_accept(msg)
	elif msg_type == b'\x03':
		message.dec_mes(OWN_ADDR, msg)
	elif msg_type == b'\x04':
		dec_destroy(msg)

def dec_invite(msg):
	sender_id = msg[5:6]
	sender = sender_id.decode()
	n = int.from_bytes(msg[6:8], byteorder='big')
	print(sender)
	# verify signature
	pubkeyfile = NET_PATH + '/' + sender + '/' + 'pubkey.pem'
	pubkey = genkey.load_publickey(pubkeyfile)
	verifier = pss.new(pubkey)
	hashfn = SHA256.new()
	hashfn.update(msg[0:-256])
	signature = msg[-256:len(msg)]
	try:
		verifier.verify(hashfn, signature)
		print('Signature verification is successful.')
		start = 8
		while True:
			receiver = msg[start:start+1].decode()
			if receiver == OWN_ADDR:
				start = start+1
				enc_key = msg[start:start+256]
				privkeyfile = NET_PATH + '/' + OWN_ADDR + '/' + 'privkey.pem'
				keypair = genkey.load_keypair(privkeyfile)
				RSAcipher = PKCS1_OAEP.new(keypair)
				# Decrypt the session key with the private RSA key
				session_key = RSAcipher.decrypt(enc_key)
				sessionkeyfile = NET_PATH + '/' + OWN_ADDR + '/' + 'sskey.pem'
				with open(sessionkeyfile, 'wb') as outf:
					outf.write(session_key)
				state = 'sndsqn: ' + '0'*(n+1) + '\n'
				state += 'rcvsqn: ' + '0'*(n+1) + '\n'
				sqnfile = NET_PATH + '/' + OWN_ADDR + '/' +'sqn.txt'
				with open(sqnfile, 'wt') as tf:
					tf.write(state)
				break
			else:
				start = start+1+256
	except (ValueError, TypeError):
		print('Signature verification is failed.')

	ssidfile = NET_PATH + '/' + OWN_ADDR + '/' + 'ssid.pem'
	ssf = open(ssidfile, 'wt')
	h = SHA256.new(msg)
	ssf.write(h.hexdigest())

def dec_accept(msg):
	sender_id = msg[5:6]
	sender = sender_id.decode()
	# verify signature
	pubkeyfile = NET_PATH + '/' + sender + '/' + 'pubkey.pem'
	pubkey = genkey.load_publickey(pubkeyfile)
	verifier = pss.new(pubkey)
	hashfn = SHA256.new()
	hashfn.update(msg[0:-256])
	signature = msg[-256:len(msg)]
	try:
		verifier.verify(hashfn, signature)
		print('Signature verification is successful.')
		server_mem = NET_PATH + '/' + 'ssmem.pem'
		wf = open(server_mem, 'at')
		state = sender
		wf.write(state)
	except (ValueError, TypeError):
		print('Signature verification is failed.')

def dec_destroy(msg):
	sender_id = msg[5:6]
	sender = sender_id.decode()
	# verify signature
	pubkeyfile = NET_PATH + '/' + sender + '/' + 'pubkey.pem'
	pubkey = genkey.load_publickey(pubkeyfile)
	verifier = pss.new(pubkey)
	hashfn = SHA256.new()
	hashfn.update(msg[0:-256])
	signature = msg[-256:len(msg)]
	try:
		verifier.verify(hashfn, signature)
		print('Signature verification is successful.')
	except (ValueError, TypeError):
		print('Signature verification is failed.')

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:k', longopts=['help', 'path=', 'addr=', 'keygen'])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-k' or opt == '--keygen':
		KEYGEN = True

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if KEYGEN:
	pubkeyfile = NET_PATH + '/' + OWN_ADDR + '/' + 'pubkey.pem'
	privkeyfile = NET_PATH + '/' + OWN_ADDR +'/' + 'privkey.pem'
	genkey.gen_key(pubkeyfile, privkeyfile)

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 
	dec_msg(msg)
    

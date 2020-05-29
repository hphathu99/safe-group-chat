#!/usr/bin/env python3
#network.py

import os, sys, getopt, time
import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import genkey, session

NET_PATH = './'
ADDR_SPACE = 'ABC'
CLEAN = False
KEYGEN = False
TIMEOUT = 0.500  # 500 millisec
OPEN_SESSION = False
server_ssidfile = None
INDEX = 0

def read_msg(src):
	global last_read
	
	out_dir = NET_PATH + src + '/OUT'
	msgs = sorted(os.listdir(out_dir))

	if len(msgs) - 1 <= last_read[src]: return '', ''
	
	next_msg = msgs[last_read[src] + 1]
	dsts = next_msg.split('--')[1]
	with open(out_dir + '/' + next_msg, 'rb') as f: msg = f.read()
	read_enc(msg)
	last_read[src] += 1
	return msg, dsts

  
def write_msg(dst, msg):

	in_dir = NET_PATH + dst + '/IN'
	msgs = sorted(os.listdir(in_dir))

	if len(msgs) > 0:
		last_msg = msgs[-1]
		next_msg = (int.from_bytes(bytes.fromhex(last_msg), byteorder='big') + 1).to_bytes(2, byteorder='big').hex()
	else:
		next_msg = '0000'
	
	with open(in_dir + '/' + next_msg, 'wb') as f: f.write(msg)
	read_enc(msg)
	return

def clean_all():
	for addr in ADDR_SPACE:
		in_dir = NET_PATH + addr + '/IN'
		for f in os.listdir(in_dir): os.remove(in_dir + '/' + f)
		out_dir = NET_PATH + addr + '/OUT'
		for f in os.listdir(out_dir): os.remove(out_dir + '/' + f)
		all_dir = NET_PATH + addr
		for f in os.listdir(all_dir): 
			if f.endswith('.pem') or f.endswith('.txt'):
				os.remove(all_dir + '/' + f)
		big_dir = NET_PATH
		for f in os.listdir(big_dir): 
			if f.endswith('.pem'):
				os.remove(big_dir + '/' + f)

def create_hash(msg):
	h = SHA256.new(msg)
	return h.hexdigest()

def read_enc(msg):
	SS_SIZE = 0
	global OPEN_SESSION
	type = msg[0:1]
	server_ssidfile = NET_PATH + '/' + 'ssdetails.pem'
	
	if type == b'\x01':
		src = msg[5:6].decode()
		SS_SIZE = int.from_bytes(msg[6:8], byteorder='big')+1
		SES_ID = create_hash(msg)
		ssf = open(server_ssidfile, 'wt')
		state =  "id: " + SES_ID + '\n'
		state += "size: " + str(SS_SIZE) + '\n'
		ssf.write(state)
		session.SESSION.add(src)
		server_mem = NET_PATH + '/' + 'ssmem.pem'
		wf = open(server_mem, 'wt')
		state = "members: A"
		wf.write(state)
	elif type == b'\x02':
		src = msg[5:6].decode()
		ssidfile = 	NET_PATH + 'network' + src + '/ssid.pem' 
		if ssidfile != None:
			sender_id = msg[5:6].decode()
			hash_invite = msg[6:70].decode()
			rssf = open(server_ssidfile, 'rt')
			SES_ID = rssf.readline()[len("id: "):len("id: ")+64] # type should be byte string
			SS_SIZE = int(rssf.readline()[len("size: "):len("size: ")+1]) 
			if hash_invite == SES_ID:
				session.SESSION.add(sender_id)
	elif type == b'\x04':
		print('Server destroying...')
		

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:k:c', longopts=['help', 'path=', 'addrspace=', 'keygen', 'clean'])
except getopt.GetoptError:
	print('Usage: python network.py -p <network path> -a <address space> [--keygen] [--clean]')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python network.py -p <network path> -a <address space> [--clean]')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addrspace':
		ADDR_SPACE = arg
	elif opt == '-k' or opt == '--keygen':
		KEYGEN = True
	elif opt == '-c' or opt == '--clean':
		CLEAN = True

ADDR_SPACE = ''.join(sorted(set(ADDR_SPACE)))

if len(ADDR_SPACE) < 2:
	print('Error: Address space must contain at least 2 addresses.')
	sys.exit(1)

for addr in ADDR_SPACE:
	if addr not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
		print('Error: Addresses must be capital letters from the 26-element English alphabet.')
		sys.exit(1)

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

# if program was called with --keygen, generate new key pairs for server
if KEYGEN:
	pubkeyfile = NET_PATH + '/' + 'server_pubkey.pem'
	privkeyfile = NET_PATH + '/' + 'server_privkey.pem'
	genkey.server_gen_key(pubkeyfile, privkeyfile)

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

print('--------------------------------------------')
print('Network is running with the following input:')
print('  Network path: ' + NET_PATH)
print('  Address space: ' + ADDR_SPACE)
print('  Key pair generation requested: ', KEYGEN)
print('  Clean-up requested: ', CLEAN)
print('--------------------------------------------')

# create folders for addresses if needed
for addr in ADDR_SPACE:
	addr_dir = NET_PATH + addr
	if not os.path.exists(addr_dir):
		print('Folder for address ' + addr + ' does not exist. Trying to create it... ', end='')
		os.mkdir(addr_dir)
		os.mkdir(addr_dir + '/IN')
		os.mkdir(addr_dir + '/OUT')
		print('Done.')

# if program was called with --clean, perform clean-up here
# go through the addr folders and delete messages
if CLEAN:
	clean_all()

# initialize state (needed for tracking last read messages from OUT dirs)
last_read = {}		
for addr in ADDR_SPACE:
	out_dir = NET_PATH + addr + '/OUT'
	msgs = sorted(os.listdir(out_dir))
	last_read[addr] = len(msgs) - 1
		

# main loop
print('Main loop started, quit with pressing CTRL-C...')
while True:
	time.sleep(TIMEOUT)
	for src in ADDR_SPACE:
		msg, dsts = read_msg(src)                               # read outgoing message
		if dsts != '':											# if read returned a message...
			if dsts == '+': dsts = ADDR_SPACE					# handle broadcast address +
			for dst in dsts:									# for all destinations of the message...
				if dst in ADDR_SPACE:							# destination must be a valid address
					write_msg(dst, msg)                         # write incoming message

	
	

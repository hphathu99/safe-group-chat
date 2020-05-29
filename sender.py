#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from netinterface import network_interface
import invite
import genkey
import message
import session

NET_PATH = './'
OWN_ADDR = 'A'
KEYGEN = False
INVITE = False
INVITED = False
SES_ID = None
JOIN = False

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:k:i:j', longopts=['help', 'path=', 'addr=', 'keygen','invite', 'join'])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr> -j <session ID>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-k' or opt == '--keygen':
		KEYGEN = True
	elif opt == '-i' or opt == '--invite':
		INVITE = (OWN_ADDR == 'A') # assymption: only admin A can invite other people to the session
	elif opt == '-j' or opt == '--join':
		JOIN = True

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

if KEYGEN: 
	pubkeyfile = NET_PATH + '/' + OWN_ADDR + '/' + 'pubkey.pem'
	privkeyfile = NET_PATH + '/' + OWN_ADDR +'/' + 'privkey.pem'
	genkey.gen_key(pubkeyfile, privkeyfile)
	
netif = network_interface(NET_PATH, OWN_ADDR)

def initiate():
	dst = input('Type the people you want to invite to the group chat: ')
	content = invite.enc_invite(dst)
	netif.send_msg(dst, content)
	sessionloop()

def sessionloop():
	while True:
		msg = input('Type a message: ')
		if (msg == 'destroy'):
			print('Chat ended.')
			invite.enc_destroy(OWN_ADDR, msg)
			break
		msg = message.enc_mes(OWN_ADDR, msg)
		ssmemfile = NET_PATH + '/'+ 'ssmem.pem'
		rf = open(ssmemfile, 'rt')
		mem = list(rf.readline()[len("members: "):])
		for des in mem:
			if des != OWN_ADDR:
				netif.send_msg(des, msg)

def accept_invite():
	dst = 'A'
	ssidfile = NET_PATH + '/' + OWN_ADDR + '/' + 'ssid.pem'
	fss = open(ssidfile, 'rt')
	ssid = fss.read()
	if ssid != None: 
		content = invite.enc_accept(OWN_ADDR, ssid)
		netif.send_msg(dst, content)
		sessionloop()
	else:
		print('You are not a member of any session')


# main loop
print('Main loop started...')
while True:
	msg = input('Type a message: ')
	if (msg == 'start'):
		initiate()
	elif (msg == 'accept'):
		accept_invite()
	else:
		dst = input('Type a destination address: ')
		netif.send_msg(dst, msg)
	if input('Continue? (y/n): ') == 'n': break

import sys, getopt
from Crypto.Cipher import AES
from Crypto import Random
import session

NET_PATH = './network'
sessionkeyfile = None

def enc_mes (src, msg):
    # Get the session size from ssdetails
    ssdetails = NET_PATH + '/' + 'ssdetails.pem'
    df = open(ssdetails, 'rt')
    line1 = df.readline()
    size = df.readline()[len("size: "):]

    # Read the members size to get the index of cur src
    ssmem = NET_PATH + '/' + 'ssmem.pem'
    mf = open(ssmem, 'rt')
    mem = list(mf.readline()[len("members: "):len("members: ")+int(size)])

    # Get the sesion key from sskey
    sessionkeyfile = NET_PATH + '/' + src + '/' + 'sskey.pem'
    with open(sessionkeyfile, 'rb') as sf:
        key = sf.read()    
    
    # Get the send and receive sqn from sqnfile
    sqnfile = NET_PATH + '/' + src + '/' + 'sqn.txt'
    with open(sqnfile, 'rt') as tf:
        sndsqn = list(tf.readline()[len("sdnsqn: "):len("sdnsqn: ")+int(size)])
        rcvsqn = tf.readline()

    # Compute payload_length and set authtag_length
    payload_length = len(msg)
    authtag_length = 12 

    # Compute message length
    # header: 12 + 2*size bytes
    #    type:    1 btye
    #    version: 2 bytes
    #    length:  2 btyes
    #    sqn:     2 bytes * size
    #    rnd:     7 bytes
    #   sender:   1 byte  
    # payload: payload_length
    # authtag: authtag_length
    msg_length = 13 + 2*int(size) + payload_length + authtag_length
    msg = msg.encode('utf-8')
    # create header
    header_type = b'\x03'                                   # message type 1
    header_version = b'\x01\x02'                            # protocol version 1.2
    header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
    sender_id = src.encode()
    s = sndsqn[mem.index(src)]
    header_sqn = b''
    sndsqn[mem.index(src)] = str(int(s)+1)
    for s in sndsqn:
        header_sqn += int(s).to_bytes(2, byteorder='big')
    header_rnd = Random.get_random_bytes(7)                 # 7-byte long random value
    header = header_type + header_version + header_length + header_sqn + header_rnd + sender_id

    # Encode msg
    nonce = header_sqn + header_rnd
    AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
    AE.update(header)
    encrypted_payload, authtag = AE.encrypt_and_digest(msg)
    enc_content = header + encrypted_payload + authtag

    # Rewrite the sqnfile with updated sdnsqn
    sf = open(sqnfile, 'wt')
    sndsqn = ''.join(sndsqn)
    sqn = "sndsqn: " + sndsqn + '\n'
    sqn += rcvsqn
    sf.write(sqn)

    return enc_content

def dec_mes(src, msg):
    # Get the session size from ssdetils
    ssdetails = NET_PATH + '/' + 'ssdetails.pem'
    df = open(ssdetails, 'rt')
    line1 = df.readline()
    size = int(df.readline()[len("size: "):])

    # Read the session key file
    sessionkeyfile = NET_PATH + '/' + src + '/' + 'sskey.pem'
    with open(sessionkeyfile, 'rb') as rf:
        key = rf.read()
    
    # Get the receive sequence from sqnfile
    sqnfile = NET_PATH + '/' + src + '/' + 'sqn.txt'
    with open(sqnfile, 'rt') as tf:
        sndsqnline = tf.readline()
        rcvsqn = list(tf.readline()[len("rcvsqn: "):len("rcvsqn: ")+size])
        # print(rcvsqn)

    # Read the members size to get the index of cur src
    ssmem = NET_PATH + '/' + 'ssmem.pem'
    mf = open(ssmem, 'rt')
    mem = list(mf.readline()[len("members: "):len("members: ")+int(size)])

    # Parse the message msg
    header = msg[0:(13+2*size)]                
    authtag = msg[-12:]               
    encrypted_payload = msg[(13+2*size):-12]   
    header_type = header[0:1]      
    header_version = header[1:3]        
    header_length = header[3:5]       
    header_sqn = header[5:5+2*size]           
    header_rnd = header[5+2*size:12+2*size]    
    sender_id = header[12+2*size:13+2*size].decode()

    # # Check the msg length
    # if len(msg) != int.from_bytes(header_length, byteorder='big'):
    #     print("Warning: Message length value in header is wrong!")

    # Check the sequence number
    sndsqn = [int.from_bytes(header_sqn[i:i+2], byteorder='big') for i in range(0, len(header_sqn), 2)]
    snd = int(sndsqn[mem.index(sender_id)])
    rcv = int(rcvsqn[mem.index(sender_id)])
    # print(str(snd) + " " + str(rcv))
    if (snd <= rcv):
        print("Error: Message sequence number is too old!")
        print("Processing completed.")
        sys.exit(1)    

    # Verify and decrypt the encrypted payload
    nonce = header_sqn + header_rnd
    AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
    AE.update(header)
    try:
        payload = AE.decrypt_and_verify(encrypted_payload, authtag)
    except Exception as e:
        print("Error: Operation failed!")
        print("Processing completed.")
        sys.exit(1)
    # Update increase rcvsqn
    count = 0
    for s in rcvsqn:
        if count == mem.index(sender_id):
            s = str(int(s)+1)
            rcvsqn[mem.index(sender_id)] = s
            # print("in here")
            # print(str(rcvsqn[mem.index(sender_id)]))
        count +=1
    sqn = ""
    # Rewrite the sqnfile with updated rcvsqn
    sf = open(sqnfile, 'wt')
    sqn += sndsqnline
    sqn += "rcvsqn: " + ''.join(rcvsqn)
    sf.write(sqn)
    print(payload.decode())

    return payload.decode()



    
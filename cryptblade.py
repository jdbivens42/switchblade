#!/bin/env python3
from switchblade import Switchblade

import string
import random

import socket
import inspect

import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES
from Crypto import Random
import hashlib

def get_socket_wrapper(args, cryptors=None):
    return lambda sock, _args=args, cryptors=cryptors: wrap_socket(sock, _args, cryptors=cryptors)()

def wrap_socket(sock, _args, cryptors=None):
    if _args.verbosity > 1:
        print("Wrapping socket: {}".format(sock))
    class CryptSocket(object):
        def __init__(self, *args, **kwargs):
            if inspect.isclass(sock):
                self._cryptsock = sock(*args, **kwargs)
            else:
                self._cryptsock = sock

            self.args = _args
            self.cryptors = cryptors
            self._first_contact = False
            if self.args.verbosity > 2:
                print("Internal socket: {}".format(self._cryptsock))

        def __getattribute__(self, name):
            try:    
                x = super(CryptSocket,self).__getattribute__(name)
            except AttributeError as e:      
                pass
            else:
                return x
            x = self._cryptsock.__getattribute__(name)
            if x.__name__ == "send":
                return self._send_encrypted
            elif x.__name__ == "recv":
                return self._recv_encrypted
            else:
                return x
            #if type(x) == type(self.__init__): # it is an instance method

        def _send_encrypted(self, _bytes, *args, **kwargs):
            if self.args.verbosity > 2:
                print("Encrypting: {}".format(_bytes))
            if not self._first_contact:
                self._first_contact = True
                for c in self.cryptors:
                    c.handshake(self._cryptsock)
            for c in self.cryptors:
                if self.args.verbosity > 2:
                    print("Using {} cryptor".format(type(c).__name__))
                _bytes = c.encrypt(_bytes)
            return self._cryptsock.send(_bytes, *args, **kwargs)

        def _recv_encrypted(self, *args, **kwargs):
            _bytes = self._cryptsock.recv(*args, **kwargs)
            if self.args.verbosity > 2:
                print("Decrypting: {}".format(_bytes))
            if not self._first_contact:
                self._first_contact = True
                for c in self.cryptors[::-1]:
                    c.handshake(self._cryptsock) 
            
            for c in self.cryptors[::-1]:
                if self.args.verbosity > 2:
                    print("Using {} cryptor".format(type(c).__name__))
                _bytes = c.decrypt(_bytes)
            return _bytes

    return CryptSocket

        
class Cryptblade(Switchblade):
    def print_banner(self):
        self.print_local("""

*********************************************************************************************
*                                                                                           *
*    ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██████╗ ██╗      █████╗ ██████╗ ███████╗      *
*    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝     *
*    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██████╔╝██║     ███████║██║  ██║█████╗       *
*    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══██╗██║     ██╔══██║██║  ██║██╔══╝       *
*    ╚██████╗██║  ██║   ██║   ██║        ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗     *
*     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝     *
*                                                                                           *
*********************************************************************************************
                                                                                  
""")

    @staticmethod
    def rand_key(size=32, use_digits=True):
        digits = ""
        if use_digits:
            digits = string.digits 
        return ''.join(random.choices(string.ascii_letters + digits, k=size))

    @staticmethod
    def get_parser():
        parser = Switchblade.get_parser()
        # TODO: consider adding mutliple keys
        parser.add_argument('--encrypt', help="Encrypt / decrypt communications using this algorithm. Must be one of: ['rc4', 'b64', 'b64_url', 'aes'].\n"+
                                              "You can pass multiple options to add layers of encryption / encoding", nargs="+")
        parser.add_argument('-k', '--key', help="Encrypt communications using this key / keyfile (depending on the algoritm). Use with -e (--encrypt).")
        parser.add_argument('--server_key', help="Encrypt communications using this key / keyfile (depending on the algoritm). Use with -e (--encrypt).")
        parser.add_argument('--client_key', help="Encrypt communications using this key / keyfile (depending on the algoritm). Use with -e (--encrypt).")

        return parser


######################################################################################################
class CryptModule:
    def __init__(self, local_key=None, remote_key=None, state=None):
        self.local_key = local_key
        self.remote_key = remote_key
        self.state = state

    def encrypt(self, msg):
        return msg

    def decrypt(self, msg):
        return msg

    # If a handshake, key exchange is needed before communication can
    # begin, implement it here
    def handshake(self, sock):
        pass

class B64Encode(CryptModule):
    def __init__(self, *args, urlsafe=False, **kwargs):
        super().__init__(*args, **kwargs)

        if urlsafe:
            self._encode = base64.urlsafe_b64encode
            self._decode = base64.urlsafe_b64decode
        else:
            self._encode = base64.b64encode
            self._decode = base64.b64decode

    def encrypt(self, msg):
        return super().encrypt(self._encode(msg))

    def decrypt(self, msg):
        return self._decode(super().decrypt(msg))

#####################################################
#  WIP: Need to make args for pub / private keys.
#####################################################
#class RSACrypt(CryptModule):
#    def __init__(self, *args, **kwargs):
#        super().__init__(*args, **kwargs)
#        with open(self.local_key, 'rb') as f:
#            self.pub_local = f.read()
#        with open(self.remote_key, 'rb') as f:
#            self.pub_remote = f.read()
#####################################################

class AESCrypt(CryptModule):
    # https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.BS = 16

    def pad(self, s):
        return s + (self.BS - len(s) % self.BS) * bytes([self.BS - len(s) % self.BS])
    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])] 

    def encrypt(self, msg):
        msg = self.pad(msg)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.local_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(msg)

    def decrypt(self, enc):
        iv = enc[:16]
        cipher = AES.new(self.remote_key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt( enc[16:] ))

# TODO: Fix bug - does not work with UDP
class RC4Crypt(CryptModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.state:
            self.state = {True:{}, False:{}}

    def _rc4_setup(self, key, state):
        try:
            key = [ord(c) for c in key]
        except TypeError as e:
            pass
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
        # Maintain two keystream states, one for each direction.
        # Use convention that DEcrypt direction uses the reverse of the key
        #   to reduce key reuse. The peer must reverse the key for the ENcrypt direction
        state = self.state[decrypt]
        if not 'rc4_prga' in state:
            if decrypt:
                key = self.remote_key
            else:
                key = self.local_key

            self._rc4_setup(key, state)
            state['rc4_prga'] = self._rc4_prga(state)

        msg = [ord(c) if not type(c) is int else c for c in msg]
        return bytes(msgbyte ^ keybyte for msgbyte, keybyte in zip(msg, state['rc4_prga']))
        #return bytes(b"".join([chr(ord(msgbyte) ^ keybyte) for msgbyte, keybyte in zip(msg, prga())]))

    def encrypt(self, msg):
        return super().encrypt(self.rc4(msg, decrypt=False))

    def decrypt(self, msg):
        return self.rc4(super().decrypt(msg), decrypt=True)

###########################################################
#
#       Driver
#
###########################################################

if __name__=="__main__":
    parser = Cryptblade.get_parser()
    args = parser.parse_args()
    supported = ['rc4', 'b64', 'b64_url', 'aes']
    assert not bool(args.server_key) != bool(args.client_key), "Either use just --key or both --client_key and --server_key"
    assert bool(args.key) != bool(args.server_key or args.client_key), "Either use just --key or both --client_key and --server_key"

    #TODO add validation that checks that keys are present when necessary
    cryptors = []
    for alg in  args.encrypt:
        if alg not in supported:
            Exception('Encryption algorithm {} not available. Try one of {}'.format(args.encrypt, supported))

        # assertions mean that if this is true, then only args.key is set
        if args.key:
            args.server_key = args.key
            args.client_key = args.key[::-1]
                
            if not args.listen:
                # every client internally things it is a server, but when we run the command, we want
                # the --server_key and --client_key args to match on both boxes
                args.server_key, args.client_key = args.client_key, args.server_key
        # now server_key and client_key are set

        # things that don't take keyfiles
        if alg in ['rc4', 'aes']:
            assert args.server_key and args.client_key, "Keys are required for {}".format(alg)
            if len(args.server_key) < 32:
                args.server_key = hashlib.sha256(args.server_key.encode()).digest()
            if len(args.client_key) < 32:
                args.client_key = hashlib.sha256(args.client_key.encode()).digest()

        cryptor = None        
        if alg == "rc4":
            cryptor = RC4Crypt(local_key=args.server_key, remote_key=args.client_key)
        elif alg == "b64":
            cryptor = B64Encode(urlsafe=False)
        elif alg == "b64_url":
            cryptor = B64Encode(urlsafe=True)
        elif alg == "aes":
            cryptor = AESCrypt(local_key=args.server_key, remote_key=args.client_key)

        if not cryptor:
            raise Exception("Failed to get a Cryptor for {}".format(alg))
        cryptors.append(cryptor)
    sb = Cryptblade(args, wrap_sock=get_socket_wrapper(args, cryptors=cryptors))
    sb.listener()


#!/bin/env python3
from switchblade import Switchblade

import string
import random

class Cryptblade(Switchblade):
    #def __init__(self, args):
    #    super().__init__(args)

    @staticmethod
    def rand_key(size=32, use_digits=True):
        digits = ""
        if use_digits:
            digits = string.digits 
        return ''.join(random.choices(string.ascii_letters + digits, k=size))

    @staticmethod
    def get_parser():
        parser = Switchblade.get_parser()
        parser.add_argument('-e', '--encrypt', help="Encrypt / decrypt communications using this algorithm. Must be one of: [rc4]")
        parser.add_argument('-k', '--key', help="Encrypt communications using this key / keyfile (depending on the algoritm). Use with -e (--encrypt).")

        return parser

###########################################################
# RC4

    def _rc4_setup(self, key):
        key = [ord(c) for c in key]
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        # Store the current crypto state for later
        self._crypto.update({'key':key, 'S':S, 'i':0, 'j':0})

    def _rc4_prga(self):
        # Restore state of the crypto algorithm
        S, i, j = [self._crypto[x] for x in ['S','i','j']]
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
            self._crypto = {}
        if not 'rc4_prga' in self._crypto:
            self._rc4_setup(self.args.key)
            self._crypto['rc4_prga'] = self._rc4_prga()

        msg = [ord(c) if not type(c) is int else c for c in msg]
        return bytes(msgbyte ^ keybyte for msgbyte, keybyte in zip(msg, self._crypto['rc4_prga']))
        #return bytes(b"".join([chr(ord(msgbyte) ^ keybyte) for msgbyte, keybyte in zip(msg, prga())]))
###########################################################
    def _crypt(self, msg, direction=False):
        if self.args.encrypt:
            # Should throw AttributeError on failure
            try:
                msg = getattr(self, self.args.encrypt)(msg, decrypt=direction)
            except AttributeError as e:
                print("Encryption algorithm {} is not supported. Exiting.".format(self.args.encrypt))
                self.exit("")
        return msg

    def encrypt(self, msg):
        return self._crypt(msg, False)
    def decrypt(self, msg):
        return self._crypt(msg, True)

    # Overrides Switchblade
    def _send(self,cmd): 
        cmd = self.encrypt(cmd)
        self.nc.send(cmd) 
 
    # Overrides Switchblade
    def _recv(self): 
        msg = super()._recv()
        if msg: 
            return self.decrypt(msg)
        return msg

if __name__=="__main__":
    parser = Cryptblade.get_parser()
    sb = Cryptblade(parser.parse_args())
    sb.listener()


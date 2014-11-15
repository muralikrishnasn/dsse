#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Client side implementation of DSSE
'''

import sys
import os
import re
import hashlib
import random
import pickle
import math
from Crypto.Cipher import AES

class DSSEClient:
    z_value = 100


    def opener(self, filename, mode):
        file = None
        try:
            file = open(filename, mode)
        except IOError:
            print "Could not open {0} for reading.".format(filename)
        return file
    
    
    def closer(self, file):
        try:
            file.close()
        except IOError:
            print "Could not close file."
    
    
    def totalsize(self, files):
        sum = 0
        for file in files:
            try:
                sum += os.path.getsize(file)
            except os.error:
                print "Unable to get size of {0}.".format(file)
        return sum

    
    # This is the tokenizer. Replace this function whenever the input isn't text-based.
    def fbar(self, f):
        fbar = []
        # Match anything that isn't alphanumeric or space
        stripper = re.compile(r'([^\s\w])+')
        with open(filename,'r') as f:
            for line in f:
                line = stripper.sub('', line)
                words = line.split()
                for word in words:
                    if word not in fbar:
                        fbar.append(word)
        return fbar


    def F(self, data):
        return hashlib.sha256(self.K1 + data).digest()
    
    
    def G(self, data):
        return hashlib.sha256(self.K2 + data).digest()

    
    def P(self, data):
        return hashlib.sha256(self.K3 + data).digest()
    

    def H1(self, data):
        return hashlib.sha512("076c61ed3aa289f970d5477b72f0e8c9d6839a5575836eb91aad23a0ee31ac58766194b49b6c277de4357bd94cbfb5127d9fe6a94eb6ad0027722cfa9cbd67d1" + data).digest()
    

    def H2(self, data):
        return hashlib.sha512("e2d86abcd967fccc36fad7219690f6e8fa2b85ea7631d992af2d4e940962b1225349d2dde0d31f3251d1f037d53741fd0a706fdb36d4a70ef3c44e13a3224753" + data).digest()


    def filehashes(self, filename):
        id = hashlib.sha1()         # Only used to identify file, no cryptographic use
        Ff = hashlib.sha256(self.K1)
        Gf = hashlib.sha256(self.K2)
        Pf = hashlib.sha256(self.K3)
        with open(filename,'rb') as f: 
            for chunk in iter(lambda: f.read(128 * id.block_size), b''):
                id.update(chunk)
                Ff.update(chunk)
                Gf.update(chunk)
                Pf.update(chunk)
        return (id.digest(), Ff.digest(), Gf.digest(), Pf.digest())


    def findusable(self, array):
        arrlen = len(array)
        rndbytes = int(math.ceil(math.log(arrlen, 256)))
        while True:
            addr = int(os.urandom(rndbytes).encode('hex'),16) % arrlen
            if array[addr] is not None:
                break
        return addr


    # TODO: test
    # We opt to use AES because obviously.
    def SKE(self, filename):
        iv = os.urandom(16)
        cipher = AES.new(self.K4, AES.MODE_CFB, iv)
        with open(filename, 'rb') as src:
            with open(filename + ".enc", 'wb') as dst:
                dst.write(iv)
                for chunk in iter(lambda: src.read(AES.block_size * 128), b''):
                    if len(chunk) != AES.block_size * 128:
                        break
                    dst.write(cipher.encrypt(chunk))
                if len(chunk) == AES.block_size * 128:
                    dst.write(cipher.encrypt(chr(16) * 16))
                else:
                    remainder = len(chunk) % 16
                    if remainder == 0:
                        remainder = 16
                    chunk += chr(remainder) * remainder
                    dst.write(cipher.encrypt(chunk))



    def __init__(self):
        self.K1 = 0
        self.K2 = 0
        self.K3 = 0
        self.K4 = 0
    

    def Gen(self):
        self.K1 = os.urandom(32)
        self.K2 = os.urandom(32)
        self.K3 = os.urandom(32)
        self.K4 = os.urandom(32)
        self.keys = [self.K1, self.K2, self.K3, self.K4]
        return self.keys


    def Enc(self, files):
        bytes = self.totalsize(files)
        iddb = {}

        # Step 1
        As = [None] * (bytes + DSSEClient.z_value)
        Ad = [None] * (bytes + DSSEClient.z_value)
        Ts = {}
        Td = {}
        
        # Steps 2 and 3, interleaved
        for filename in files:
            (id, Ff, Gf, Pf) = self.filehashes(filename)
            iddb[id] = filename
            rp = os.urandom(32)
            H2 = self.H2(Pf + rp)
            for w in self.fbar(filename):
                addr_As = findusable(As)    # insert new node here
                addr_Ad = findusable(Ad)    # insert dual node here
                r = os.urandom(32)
                Fw = self.F(w)
                Gw = self.G(w)
                Pw = self.P(w)
                H1 = self.H1(Pw + r)
                
                ### PSEUDOCODE ###
                # TODO: how to XOR Ts_entry?
                # TODO: define zerostring
                if Fw in Ts:
                    Ts_entry = Ts[Fw]
                    Ts_entry ^= Gw
                    N1 = Ts_entry[0]
                    Nstar1 = Ts_entry[1]
                else:
                    N1 = zerostring
                    Nstar1 = zerostring
                # TODO: build N
                #N = 
                #As[addr_As] = N
                
                # Update Ts (addrN* is addr_Ad)
                
                # TODO: D, update Td
                # TODO: need to use previous D entry (perhaps!), store outside loop

                ### END PSEUDOCODE ###

        # Step 4
        Fz = []
        Fpz = []
        for idx in range(DSSEClient.z_value):
            Fz.append(self.findusable(As))
            Fpz.append(self.findusable(Ad))
        Ts[None] = Fz[-1] + zerostring
        
        # Supposed to go from Fz down to F1 but it's a random selection so it's the same.
        for idx in range(len(Fz - 1)):
            As[Fz[idx]] = zerostring + Fz[idx + 1] + Fpz[idx]
        As[Fz[-1]] = zerostring + zerostring + Fpz[-1]


        # Step 5
        # FIXME: currently this used A LOT of entropy
        for idx in range(len(As)):
            if As[idx] is None:
                As[idx] = os.urandom(64)    # FIXME: no idea how long entries are!
            if Ad[idx] is None:
                Ad[idx] = os.urandom(64)    # FIXME: no idea how long entries are!

        # Step 6
        for filename in files:
            self.SKE(filename)
        
        # Step 7
        # Pickle As, Ts, Ad, Td, iddb

    
    def SrchToken():
        pass


    def AddToken():
        pass


    def DelToken():
        pass


    def Dec():
        pass


if __name__ == "__main__":
    dsse = DSSEClient()
    dsse.Gen()
    dsse.SKE('testfile')
    
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


    def keyedhash(self, data):
        h = hashlib.sha256()
        h.update(data)
        return h.digest()


    def F(self, data):
        return self.keyedhash(self.K1 + data)
    
    
    def G(self, data):
        return self.keyedhash(self.K2 + data)

    
    def P(self, data):
        return self.keyedhash(self.K3 + data)
    

    def oracle(self, data):
        h = hashlib.sha512()
        h.update(data)
        return h.digest()


    def H1(self, data):
        return self.oracle("076c61ed3aa289f970d5477b72f0e8c9d6839a5575836eb91aad23a0ee31ac58766194b49b6c277de4357bd94cbfb5127d9fe6a94eb6ad0027722cfa9cbd67d1" + data)
    

    def H2(self, data):
        return self.oracle("e2d86abcd967fccc36fad7219690f6e8fa2b85ea7631d992af2d4e940962b1225349d2dde0d31f3251d1f037d53741fd0a706fdb36d4a70ef3c44e13a3224753" + data)


    # FIXME: if time, refactor? If so, use word hashes, too
    def filehashes(self, filename):
        id = hashlib.sha1()         # Only used to identify file, no cryptographic use
        Ff = hashlib.sha256()
        Gf = hashlib.sha256()
        Pf = hashlib.sha256()
        Ff.update(self.K1)
        Gf.update(self.K2)
        Pf.update(self.K3)
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
        
        # Pre-allocated with |c|/8 + freesize where c is size of ciphertexts in bits.
        As = [None] * (bytes + 100)
        Ad = [None] * (bytes + 100)
        Ts = {}
        Td = {}
        
        for filename in files:
            (id, Ff, Gf, Pf) = self.filehashes(filename)
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
                


        # Build free list
        # Fill rest of As and Ad with randomness
        # Encrypt each file with SKE
        # Return index and ciphertexts
        

    
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
    arr = [1] * 500
    arr[328] = None
    print dsse.findusable(arr)
    
    
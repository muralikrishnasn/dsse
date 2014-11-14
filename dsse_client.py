#!/usr/bin/python
# -*- coding: utf-8 -*-


"""
Client side implementation of DSSE
"""

'''
TODO:
	-do we need both Kx and keys?
	-Would it work to store not the keys but the pre-initialized hashes, and then to clone 'em?
'''

import sys
import os
import re
import hashlib
import random
import pickle
from Crypto.Cipher import AES

'''
    H1: SHA512
    H2: SHA512 but with a twist?
    id_i: md5    (only identifies, doesn't need to be cryptographically secure)
    F, G, P: SHA256
    SKE: AES
'''

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
        for line in f:
            line = stripper.sub('', line)
            words = line.split()
            for word in words:
            	if word not in fbar:
                	fbar.append(word)
        return fbar


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


    # Placeholder!
    def id(self, file):
    	return os.urandom(2)
    

    def Enc(self, files):
        # get bytesize of sum(files)
        bytes = self.totalsize(files)
        print bytes
        
        #Arrays pre-allocated with |c|/8 + freesize where c is size of ciphertexts in bits
        As = [None] * (bytes + 100)
        Ad = [None] * (bytes + 100)
        Ts = {}
        Td = {}
        
        # For each file:
        for filename in files:
            file = self.opener(filename, 'r')
            if file is None:
                continue
            id = getfileid(file)
            # Build As and Ad concurrently using fbar:
            for w in self.fbar(file):
            	
                # Take next word from fbar, lookup and append to As
                r_i = os.urandom(32)
                H = self.H1(self.P(w) + r_i)
                	
                # If not in Ts already:
                	# Add entry to Ts
                # Else:
                	# Change addr, update Ts
                	
                
                
                
                
                # Using address in As, build entry in Ad (problem: need preceding address, too)
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
    dsse.Gen()
    print len(dsse.F("word"))
    dsse.Enc(files=["./f", "./dsse_client.py"])
    
    
    
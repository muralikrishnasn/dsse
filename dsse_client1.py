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
	
	# Constant Parameters
    Z_VALUE = 100
	ENC_FILENAME_SIZE = 20								# Sha1
	STD_ADDR_SIZE = 16
	KEY_LENGTH = 32
	As_ENTRY_SIZE = ENC_FILENAME_SIZE + STD_ADDR_SIZE
	Ad_ENTRY_SIZE = 6 * STD_ADDR_SIZE + KEY_LENGTH
	ZEROS = "".zfill(STD_ADDR_SIZE)						# paper's method leaks info -> can distinquish last node


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
		
	def splitter(self, entry, splitPt):
		lh = entry[:splitPt] 
		rh = entry[splitPt:]
		return [lh, rh]
		
		
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


    def F(self, data):								#  PRNG k x * -> k
		random.seed(self.K1 + data)
        return random.getrandbits(len(K1)*8)
    
    
    def G(self, data):								# PRNG k x * -> *
		random.seed(self.K2 + data)
        return random.getrandbits(len(K2)*8)		# Changing to -> K so as not to leak info

    
    def P(self, data):								# PRNG k x * -> k
		random.seed(self.K3 + data)
        return random.getrandbits(len(K3)*8)
    
	 
    def H1(data):									# Random oracle * x * -> *
		random.seed(hashlib.sha512(data))
        return random.getrandbits(len(data)*8)
    

    def H2(data):									# Random oracle * x * -> *
		random.seed(hashlib.sha256(data))
        return random.getrandbits(len(data)*8)


    def findusable(self, array):						# Finds random unused cell in array
			addr = random.randrange(len(array))			# Take random address and check
			if array[] is not None
				break
		return addr


    # TODO: test
    def SKE(self, filename):
        iv = os.urandom(STD_ADDR_SIZE)
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
        self.K1 = os.urandom(KEY_LENGTH)
        self.K2 = os.urandom(KEY_LENGTH)
        self.K3 = os.urandom(KEY_LENGTH)
        self.K4 = os.urandom(KEY_LENGTH)
        self.keys = [self.K1, self.K2, self.K3, self.K4]
        return self.keys
		
	def Pad(self, addr, totalByteSize)
		return str(addr).zfill(totalByteSize - len(str(addr)))

		
	class Node:
		def __init__(self, cargo, random):
			self.cargo= cargo
			self.random  = random
	
	def parseSrcNode(nAddr, key):
		N = As[int(nAddr)]
		NInfo = N.cargo ^ H1(key, N.random)
		(id, next_addr_N) = splitter(NInfo, ENC_FILENAME_SIZE)		
		return [id, next_addr_N]										# hmm...return ID in plaintext
	
	def parseDelNode(nAddr, key):										# Yuck
		N = Ad[int(nAddr)]
		NInfo = N.cargo ^ H2(key, N.random)
		(allAddrs, FKw) = splitter(NInfo, (6*STD_ADDR_SIZE))
		(NStarAddrs, NAddrs) = splitter(allAddrs, (3*STD_ADDR_SIZE))
		(NStarAddr, prev_next_NstarAddr) = splitter(NStarAddrs, (STD_ADDR_SIZE))
		(NAddr, prev_next_NAddr) = splitter(NAddrs, (STD_ADDR_SIZE))
		(prev_NstarAddr, next_NstarAddr) = splitter(prev_next_NstarAddr, (STD_ADDR_SIZE))
		(prev_NAddr, next_NAddr) = splitter(prev_next_NAddr, (STD_ADDR_SIZE))
		return [NStarAddr, prev_NstarAddr, next_NstarAddr, NAddr, prev_NAddr, next_NAddr, FKw]
	
    def Enc(self, files):
        bytes = self.totalsize(files)
        iddb = {}

        # Step 1
        As = [None] * (bytes + DSSEClient.Z_VALUE)
        Ad = [None] * (bytes + DSSEClient.Z_VALUE)
        Ts = {}
        Td = 
		# ZEROS = "".zfill(int(math.ceil(math.log(bytes + DSSEClient.Z_VALUE)))) # (log #As)-length of 0's
		next_addr_As = ZEROS
		next_addr_Ad = ZEROS
		prev_addr_As = ZEROS
		prev_addr_Ad = ZEROS
        
		# Steps 2 and 3, interleaved
        for filename in files:
            encFilename = hashlib.sha1(filename).digest()	# 20 byte hash
            iddb[id] = encFilename
           
		    for w in self.fbar(filename):
                addr_As = findusable(As)		    		# insert new As node here
				addr_Ad = findusable(Ad)    				# insert dual node here
              
				# Build Node				
				Kw = P(w)									# 32 bytes
				r = os.urandom(4)							# need 4 bytes for encID
				encID = (encFilename + Pad(next_addr_As, STD_ADDR_SIZE)) ^ H1(Kw + r)
                N = Node(encID, r)
                As[addr_As] = N
              
				# Build NodeStar
				Kf = P(encFilename)							# Using encFilename to hide in DelToken()
				r = os.urandom(96)							# need 128-32=96 bytes for encDual
				encDual = (	Pad(addrdD+1, STD_ADDR_SIZE) + \			# addrdD + 1 (has to be addr_Ad, no? But why?)
							Pad(prev_addr_Ad, STD_ADDR_SIZE) + \		# addrdN* - 1
							Pad(next_addr_Ad, STD_ADDR_SIZE) + \		# addrdN* + 1
							Pad(addr_As, STD_ADDR_SIZE) + \				# addrsN
							Pad(prev_addr_As, STD_ADDR_SIZE) + \		# addrsN - 1
							Pad(next_addr_As+1, STD_ADDR_SIZE) + \		# addrsN + 1
							F(w) )
							^ H2(Kf + r)
                NStar = Node(encDual, r)
                Ad[addr_Ad] = NStar
				
				# Store pointer to 1st node in Lw
				FKw = F(w)
                if FKw in Ts:								# Existing word
					addrs = Pad(addr_As, STD_ADDR_SIZE) + Pad(addr_Ad, STD_ADDR_SIZE)
                    Ts[FKw] = (addrs) ^ G(w)
                    next_addr_As = addr_As
                    next_addr_Ad = addr_Ad
                else:										# New word
                    next_addr_As = ZEROS
                    next_addr_Ad = ZEROS
                
				# Store pointer to 1st node in Lf
				FKf = F(encFilename)
                if FKf in Td:								# Existing file
					addrD = Pad(addr_Ad, STD_ADDR_SIZE*2)
                    Td[FKf] = addrD ^ G(encFilename)
                    prev_addr_As = addr_As					# ??
                    prev_addr_Ad = addr_Ad					# ??
                else:										# New file
                    prev_addr_As = ZEROS					# ??
                    prev_addr_Ad = ZEROS					# ??

        # Step 4
        Fz = []
        Fpz = []
        for idx in range(DSSEClient.Z_VALUE):
            Fz.append(self.findusable(As))
            Fpz.append(self.findusable(Ad))
        Ts[free] = Pad(Fz[-1], STD_ADDR_SIZE) + ZEROS
        
        # Supposed to go from Fz down to F1 but it's a random selection so it's the same.
        for idx in range(len(Fz - 1)):
			As[Fz[idx]] = Pad(Fz[idx + 1], 18) Pad(Fpz[idx], 18) 	# Pad to 18 bytes to split easier
        As[Fz[-1]] =  "".zfill(18) + Pad(Fpz[-1], 18)


        # Step 5
        # FIXME: currently this used A LOT of entropy --> Let's just use it. The demo will be small.
        for idx in range(len(As)):
            if As[idx] is None:
                As[idx] = os.urandom(As_ENTRY_SIZE)
            if Ad[idx] is None:
                Ad[idx] = os.urandom(Ad_ENTRY_SIZE)

        # Step 6
		cipher_txts = []
        for filename in files:
            cipher_txts.append(self.SKE(filename))
        
        # Step 7								You do - I don't do pickles
        # TODO: pickle As, Ts, Ad, Td, iddb

    
    def SrchToken(self, w):
		tauS = [F(encFilename), G(encFilename), P(encFilename)]
        return tauS


	def Search(aPickle, cipher_txts, tauS):
		(t1, t2, t3) = tauS									# Step 1
		# Do some unpickling
		
		(s1, s2) = splitter((Ts[t1] ^ t2), STD_ADDR_SIZE)	# Step 2
		
		(id, next_addr_N) = parseSrcNode(s1, t2)	# Step 3
		
		cipher_txts = []
		while (next_addr_N != ZEROS):						# Step 4
			cipher_txts.append(self.SKE(id))
			(id, next_addr_N) = parseSrcNode(next_addr_N, t2, t3)
		
		return cipher_txts									# Step 5
	
    def AddToken(self, files):
		tauA = []
		for filename in files:
            encFilename = hashlib.sha1(filename).digest()
            iddb[id] = encFilename
           
		    for w in self.fbar(filename
			# TODO: finish


    def DelToken(self, filename):
		encFilename = hashlib.sha1(filename).digest()
		tauD = [F(encFilename), G(encFilename), P(encFilename), encFilename]
        return tauD


    def Del(aPickle, cipher_txts, tauD):
		(t1, t2, t3, id) = tauD													# Step 1
		
		(zeross, si) = splitter((td[t1] ^ t2), STD_ADDR_SIZE)					# Step 2
		delF = Td[int(si)]
		
		while True:																# Step 3
			(s1, s2, s3, s4, s5, s6, FKw) = parseDelNode(si, t3)
			Ad[si] = random.randrange(Ad_ENTRY_SIZE)							# 3b TODO: ck if prev_NAddr is correct one
			(lastFree, zeross) = splitter((Ts[free]), STD_ADDR_SIZE)			# 3c
			Ts[free] = s4 + ZEROS												# 3d
			A[int(s4)] = lastFree + si											# 3e
			(b1, b2) = splitter(Node(Ts[int(s5)]).cargo, STD_ADDR_SIZE)			# 3f
			r = Node(Ts[int(s5)]).random
			Ts[int(s5)] = Node((b1 + (b2 ^ s4 ^ s6)), r)
			
			(allAddrs, FKw) = splitter(Node(Td[int(s2)]).cargo, 6*STD_ADDR_SIZE)
			(NSas, Nas) = splitter(allAddrs, (3*STD_ADDR_SIZE))
			(b1, pnNSa) = splitter(NSas, (STD_ADDR_SIZE))
			(b4, pnNa) = splitter(Nas, (STD_ADDR_SIZE))
			(b2, b3) = splitter(pnNSa, (STD_ADDR_SIZE))
			(b5, b6) = splitter(pnNa, (STD_ADDR_SIZE))
			r = Node(Td[int(s2)]).random
			Ts[int(s2)] = Node( b1+b2+(b3^si^s3)+b4+b5+(b6^s4^s6)+FKw, r)
			
			(allAddrs, FKw) = splitter(Node(Td[int(s3)]).cargo, 6*STD_ADDR_SIZE)	#3g
			(NSas, Nas) = splitter(allAddrs, (3*STD_ADDR_SIZE))
			(b1, pnNSa) = splitter(NSas, (STD_ADDR_SIZE))
			(b4, pnNa) = splitter(Nas, (STD_ADDR_SIZE))
			(b2, b3) = splitter(pnNSa, (STD_ADDR_SIZE))
			(b5, b6) = splitter(pnNa, (STD_ADDR_SIZE))
			r = Node(Td[int(s3)]).random
			Ts[int(s3)] = Node( b1+(b2^si^s2)+b3+b4+(b5^s4^s5)+b6+FKw, r)
			
			if (s2 == ZEROS):													#TODO: confirm s2
				break
				
			si = s1																# 3h
		
	new_cipher_txts = []
	for c in cipher_txts:													# Step 4
		if (c != delF)
			new_cipher_txts.append(c)
		
	TauD = [t2, t3, id]														# Step 5 ?
		
		# TODO: pickle stuff
		
		return [gamma, new_cipher_txts]
			
			
	def Dec(self, cipher_txts):
		files = []
		for c in cipher_txts:
			files.append(self.SKE(c))
		return files
	
if __name__ == "__main__":
    dsse = DSSEClient()
    dsse.Gen()
    dsse.SKE('testfile')
    
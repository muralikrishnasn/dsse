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
import array
import string
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
    def fbar(self, filename):
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
        hash = hashlib.sha256(self.K2 + data)
        G = hash.digest()
        while 2 * self.addr_size > len(G):
            G += hash.update(self.K2).digest()
        return G[:2 * self.addr_size]

    
    def P(self, data):
        return hashlib.sha256(self.K3 + data).digest()
    

    def H1(self, data, length):
        hash = hashlib.sha512(self.xors(self.K1, self.K2) + data)
        H1 = hash.digest()
        while length > len(H1):
            hash.update(self.xors(self.K1, self.K2))
            H1 += hash.digest()
        return H1[:length]
        
        
    def H2(self, data, length):
        hash = hashlib.sha512(self.xors(self.K3, self.K2) + data)
        H2 = hash.digest()
        while length > len(H2):
            hash.update(self.xors(self.K3, self.K2))
            H2 += hash.digest()
        return H2[:length]


    def filehashes(self, filename, length):
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
        Gfstring = Gf.digest()
        while length > len(Gfstring):
            Gfstring += Gf.update(self.K2).digest()
        return (id.digest(), Ff.digest(), Gfstring[:length], Pf.digest())


    def findusable(self, array):
        while True:
            addr = random.randrange(len(array))
            if array[addr] is None:
                break
        return addr


    # TODO: test
    # We opt to use AES because it is a well-vetted standard.
    def SKEEnc(self, filename):
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
    
    
    def SKEDec(self, filename):
        with open(filename, 'rb') as src:
            #with open(string.strip(filename, ".enc"), 'wb+') as dst:
            with open("testoutput", 'wb+') as dst:
                iv = src.read(16)
                cipher = AES.new(self.K4, AES.MODE_CFB, iv)
                for chunk in iter(lambda: src.read(AES.block_size * 128), b''):
                    dst.write(cipher.decrypt(chunk))
                dst.seek(-1, os.SEEK_END)
                lastbyte = dst.read(1)
                dst.seek(-int(lastbyte.encode('hex'), 16), os.SEEK_END)
                dst.truncate()
                

    def xors(self, str1, str2):
        if len(str1) != len(str2):
            print "Strings of unequal length: {} and {}".format(len(str1), len(str2))
            test = 0/0
            return None
        a1 = array.array('B', str1)
        a2 = array.array('B', str2)
        ret = array.array('B')
        for idx in range(len(a1)):
            ret.append(a1[idx] ^ a2[idx])
        return ret.tostring()


    def pad(self, addr):
        return str(addr).zfill(self.addr_size)


    def split(self, entry, splitPt):
        lhs = entry[:splitPt] 
        rhs = entry[splitPt:]
        return lhs, rhs
        

    def __init__(self, k, z):
        self.K1 = 0
        self.K2 = 0
        self.K3 = 0
        self.K4 = 0
        self.k = k
        self.z = z
        self.id_size = 20       # SHA1 is used for file ID and is 20 bytes long
    

    def Gen(self):
        self.K1 = os.urandom(self.k)
        self.K2 = os.urandom(self.k)
        self.K3 = os.urandom(self.k)
        self.K4 = os.urandom(self.k)
        self.keys = (self.K1, self.K2, self.K3, self.K4)
        return self.keys


    def Enc(self, files):
        bytes = self.totalsize(files)
        iddb = {}

        # Step 1
        As = [None] * (bytes + self.z)
        Ad = [None] * (bytes + self.z)
        addr_size = int(math.ceil(math.log(len(As), 10)))
        zerostring = "\0" * addr_size
        self.addr_size = addr_size
        Ts = {}
        Td = {}
        
        # Steps 2 and 3, pass one
        for filename in files:
            (id, Ff, Gf, Pf) = self.filehashes(filename, addr_size)
            iddb[id] = filename
            
            addr_d_D1 = zerostring      # Temporary Td pointer to build Di chain
            
            for w in self.fbar(filename):
                addr_As = self.pad(self.findusable(As))    # insert new node here
                addr_Ad = self.pad(self.findusable(Ad))    # insert dual node here
                r = os.urandom(self.k)
                Fw = self.F(w)
                Gw = self.G(w)
                Pw = self.P(w)
                H1 = self.H1(Pw + r, addr_size)

                if Fw in Ts:
                    Ts_entry = Ts[Fw]
                    Ts_entry = self.xors(Ts_entry, Gw)
                    addr_s_N1, addr_d_N1 = self.split(Ts_entry, addr_size)
                else:
                    addr_s_N1 = zerostring
                    addr_d_N1 = zerostring

                Ts_entry = self.xors(addr_As + addr_Ad, Gw)
                Ts[Fw] = Ts_entry

                searchnode = self.xors(id + self.pad(addr_s_N1), self.H1(Pw + r, 20 + addr_size)) + r
                As[int(addr_As)] = searchnode

                '''
                addr_d_nextD = addr_d_D1
                addr_d_prevNstar = zerostring                           # addr_d((N-1)*)
                addr_d_nextNstar = addr_d_N1                            # addr_d((N+1)*)
                addr_s_N = addr_As
                addr_s_prevN = zerostring
                addr_s_nextN = addr_s_N1
                '''
                deletenode = addr_d_D1 + zerostring + addr_d_N1 + addr_As + zerostring + addr_s_N1 + Fw
                rp = os.urandom(self.k)
                H2 = self.H2(Pf + rp, 6 * addr_size + self.k)

                deletenode = self.xors(deletenode, H2) + rp
                
                Ad[int(addr_Ad)] = deletenode
    
                # We get the dual of N+1. From its perspective we are N-1.
                # Then we update its values to point to us.
                if addr_d_N1 != zerostring:
                    prevD = Ad[int(addr_d_N1)]       
                    # set prevD's second field to addr_Ad and fifth field to addr_As
                    xorstring = zerostring + addr_Ad + 2 * zerostring + addr_As + zerostring + len(self.K1) * 2 * "\0"
                    prevD = self.xors(prevD, xorstring)
                    Ad[int(addr_d_N1)] = prevD
                
                addr_d_D1 = addr_Ad     # update the temporary Td pointer

            Td[Ff] = self.xors(addr_d_D1, Gf)

        # Step 4
        Fz = []
        Fpz = []
        for idx in range(self.z):
            Fz.append(self.findusable(As))
            Fpz.append(self.findusable(Ad))
        Ts['free'] = self.pad(Fz[-1]) + zerostring
        
        # Supposed to go from Fz down to F1 but it's a random selection so it's the same.
        freezerostring = int(math.ceil(math.log(len(files), 10))) * "\0"
        for idx in range(len(Fz) - 1):
            As[Fz[idx]] = freezerostring + self.pad(Fz[idx + 1]) + self.pad(Fpz[idx])
        As[Fz[-1]] = freezerostring + zerostring + self.pad(Fpz[-1])

        # Step 5
        for idx in range(len(As)):
            if As[idx] is None:
                As[idx] = os.urandom(2 * addr_size)
            if Ad[idx] is None:
                Ad[idx] = os.urandom(6 * addr_size + 2 * self.k)

        # Step 6
        for filename in files:
            self.SKEEnc(filename)

        # Step 7
        with open("as.db", "wb") as Asdb:
            pickle.dump(As, Asdb)
        
        with open("ts.db", "wb") as Tsdb:
            pickle.dump(Ts, Tsdb)

        with open("ad.db", "wb") as Addb:
            pickle.dump(Ad, Addb)

        with open("td.db", "wb") as Tddb:
            pickle.dump(Td, Tddb)

        with open("id.db", "wb") as IDdb:
            pickle.dump(iddb, IDdb)


    # TODO: do we always have the addr_size instantiated?
    def SrchToken(self, w):
        return (self.F(w), self.G(w), self.P(w))


    def AddToken():
        pass


    def DelToken(self, filename):
        (id, Ff, Gf, Pf) = self.filehashes(filename)
        return (Ff, Gf, Pf, id)


    def Dec(self, filename):
        self.SKEDec(filename)


if __name__ == "__main__":
    dsse = DSSEClient(32, 100)
    dsse.Gen()
    dsse.Enc(['file1', 'file2'])
    dsse.Dec('file1.enc')
    
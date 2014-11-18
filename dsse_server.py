#!/usr/bin/python
# -*- coding: utf-8 -*-


"""
Server side implementation of DSSE
"""

import sys
import os
import os.path
import re
import hashlib
import random
import pickle
import math

'''
    H1: SHA512
    H2: SHA512 but with a twist?
    id_i: md5    (only identifies, doesn't need to be cryptographically secure)
    F, G, P: SHA256
    SKE: AES
'''

class DSSEServer:
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


    def xor(self, str1, str2):
        # FIXME: this is for testing purposes and should be changed/removed for final
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


    def split(self, entry, splitPt):
        lhs = entry[:splitPt]
        rhs = entry[splitPt:]
        return lhs, rhs


    def H1(self, data):
        hash = hashlib.sha512("4f6a3f7e2ea5729b7a02549f96df9fec" + data)
        H1 = hash.digest()
        while 20 + self.addr_size > len(H1):
            hash.update(data)
            H1 += hash.digest()
        return H1[:20 + self.addr_size]


    def parselamda(self, lamda):
        Fw, lamda = self.split(lamda, self.addr_size)
        Gw, lamda = self.split(lamda, self.addr_size)
        As_entry, lamda = self.split(lamda, 20 + self.addr_size)
        r, lamda = self.split(lamda, self.k)
        Ad_entry, rp = self.split(lamda, 6 * self.addr_size + self.k)
        return Fw, Gw, As_entry, r, Ad_entry, rp


    def pad(self, addr):
        return str(addr).zfill(self.addr_size)


    def __init__(self, k, addr_size):
        self.k = k
        self.As = pickle.load(open("As.db", 'rb'))
        self.Ad = pickle.load(open("Ad.db", 'rb'))
        self.Ts = pickle.load(open("Ts.db", 'rb'))
        self.Td = pickle.load(open("Td.db", 'rb'))
        self.iddb = pickle.load(open("id.db", 'rb'))
        self.addr_size = int(math.ceil(math.log(len(self.As), 10)))

    
    def Search(self, tau):
        (t1, t2, t3) = tau
        if t1 not in self.Ts:
            return []
        files = []
        addr_N, a1prime = self.split(self.xor(Ts[t1], t2), self.addr_size)
        while int(addr_N) != 0:
            N, r = self.split(As[int(addr_N)], 20 + self.addr_size)
            id, addr_N = self.split(self.xor(N, self.H1(t3, r)), 20)
            files.append(self.iddb[id])
        return files        


    def Add(self, tau):
        (t1, t2, lamda) = tau
        if t1 in Td:
            return      # file ID already in the database, let's go home
            
        # Inline: get the first free element, strip the last two addr_size elements and
        # return the length of the remaining string. This is the log #f zerostring padding
        freepadding = len(As[int(Ts['free'][:self.addr_size])][:-2*self.addr_size])
        zerostring = "\0" * self.addr_size
        prev_phistar = self.pad(0)
        for L_i in lamda:
            Fw, Gw, As_entry, r, Ad_entry, rp = self.parselamda(L_i)    # Corresponding to L_i[x]

            # 2a
            phi = self.split(self.Ts['free'], self.addr_size)[0]
            # Fetch entry in freelist, remove padding, split into both entries
            prev_phi, phistar = self.split(self.split(As[phi], freepadding)[1], self.addr_size)
            
            # 2b
            Ts['free'] = self.pad(prev_phi) + zerostring

            # 2c
            a1, a1star = self.split(self.xor(self.Ts[Fw], Gw), self.addr_size)
            
            # 2d
            self.As[phi] = self.xor(As_entry, zerostring + self.pad(a1)) + r
            
            # 2e
            self.Ts[Fw] = self.xor(phi + phistar, Gw)
            
            # 2f
            self.Ad[a1star] = self.xor(self.Ad[a1star], zerostring + phistar + \
                              2 * zerostring + phi + zerostring + + "\0" * self.k * 2)

            # 2g
            self.Ad[phistar] = self.xor(Ad_entry, prev_phistar + zerostring + a1star + \
                               phi + zerostring + a1 + Fw) + rp
        
        # 2h
        Td[t1] = self.xor(prev_phistar, t2)
        # Step 3 is performed out-of-band by simply storing a file. Caller needs to do this.

    
    def Del():
        pass
    
    
if __name__ == "__main__":
    dsse = DSSEServer(32, 5)
    
    
    
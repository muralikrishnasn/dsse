#!/usr/bin/python
# -*- coding: utf-8 -*-


"""
Server side implementation of DSSE
"""

import os
import hashlib
import random
import pickle
import math
import array

class DSSEServer:

    # After the client is done mutating the databases they should be written back to file
    def updatedatabases(self):
        with open("as.db", "wb") as Asdb:
            pickle.dump(self.As, Asdb)
        
        with open("ts.db", "wb") as Tsdb:
            pickle.dump(self.Ts, Tsdb)

        with open("ad.db", "wb") as Addb:
            pickle.dump(self.Ad, Addb)

        with open("td.db", "wb") as Tddb:
            pickle.dump(self.Td, Tddb)

        with open("id.db", "wb") as IDdb:
            pickle.dump(self.iddb, IDdb)


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


    def Hx(self, data, length):
        hash = hashlib.sha512(data)
        Hx = hash.digest()
        while length > len(Hx):
            hash.update(data)
            Hx += hash.digest()
        return Hx[:length]    


    def H1(self, data):
        return self.Hx(data, 20 + self.addr_size)


    def H2(self, data):
        return self.Hx(data, 6 * self.addr_size + self.k)


    def parselamda(self, lamda):
        Fw, lamda = self.split(lamda, self.k)
        Gw, lamda = self.split(lamda, 2 * self.addr_size)
        As_entry, lamda = self.split(lamda, 20 + self.addr_size)
        r, lamda = self.split(lamda, self.k)
        Ad_entry, rp = self.split(lamda, 6 * self.addr_size + self.k)
        return Fw, Gw, As_entry, r, Ad_entry, rp


    def parsedeletenode(self, node):
        a1, node = self.split(node, self.addr_size)
        a2, node = self.split(node, self.addr_size)
        a3, node = self.split(node, self.addr_size)
        a4, node = self.split(node, self.addr_size)
        a5, node = self.split(node, self.addr_size)
        a6, mu = self.split(node, self.addr_size)
        return a1, a2, a3, a4, a5, a6, mu


    def pad(self, addr):
        return str(addr).zfill(self.addr_size)


    def __init__(self, k = 32):
        self.k = k
        self.As = pickle.load(open("as.db", 'rb'))
        self.Ad = pickle.load(open("ad.db", 'rb'))
        self.Ts = pickle.load(open("ts.db", 'rb'))
        self.Td = pickle.load(open("td.db", 'rb'))
        self.iddb = pickle.load(open("id.db", 'rb'))
        self.addr_size = int(math.ceil(math.log(len(self.As), 10)))


    def get_address_size(self):
        return self.addr_size

    
    def Search(self, tau):
        (t1, t2, t3) = tau
        if t1 not in self.Ts:
            return []
        files = []
        addr_N, a1prime = self.split(self.xor(self.Ts[t1], t2), self.addr_size)
        while addr_N != "\0" * self.addr_size:
            N, r = self.split(self.As[int(addr_N)], 20 + self.addr_size)
            id, addr_N = self.split(self.xor(N, self.H1(t3 + r)), 20)
            files.append(self.iddb[id])
        return files        


    def Add(self, tau, filename):
        (t1, t2, lamda) = tau
        if t1 in self.Td:
            return      # file ID already in the database, let's go home

        zerostring = "\0" * self.addr_size
        prev_phistar = self.pad("\0")
        lamdacount = 0
        for L_i in lamda:
            Fw, Gw, As_entry, r, Ad_entry, rp = self.parselamda(L_i)    # Corresponding to L_i[x]

            # 2a
            lamdacount += 1
            phi = self.split(self.Ts['free'], self.addr_size)[0]
            prev_phi, phistar = self.split(self.As[int(phi)], self.addr_size)

            # 2b
            self.Ts['free'] = prev_phi + zerostring

            # 2c
            if Fw in self.Ts:
                a1, a1star = self.split(self.xor(self.Ts[Fw], Gw), self.addr_size)
            else:
                a1 = zerostring
                a1star = zerostring
            
            # 2d
            self.As[int(phi)] = self.xor(As_entry, 20 * "\0" + self.pad(a1)) + r
            
            # 2e
            self.Ts[Fw] = self.xor(phi + phistar, Gw)
            
            # 2f
            if a1star != zerostring:
                self.Ad[int(a1star)] = self.xor(self.Ad[int(a1star)], zerostring + phistar + 2 * zerostring + phi + zerostring + "\0" * self.k * 2)

            # 2g
            self.Ad[int(phistar)] = self.xor(Ad_entry, prev_phistar + zerostring + a1star + phi + zerostring + a1 + Fw) + rp
        
        # 2h
        self.Td[t1] = self.xor(prev_phistar, t2)
        
        # 3 Add filename to the iddb. Actually adding the file is done out-of-band by
        # simply storing the file with the other encrypted files.
        self.iddb[hashlib.sha1(filename).digest()] = filename

    
    def Del(self, tau):
        (t1, t2, t3, id) = tau
        if t1 not in self.Td:
            return
        
        zerostring = "\0" * self.addr_size

        addr_D = self.xor(self.Td[t1], t2)      # a1prime in the paper
        
        
        
        while addr_D != zerostring:
            # 3a
            deletenode, r = self.split(self.Ad[int(addr_D)], -self.k)
            deletenode = self.xor(deletenode, self.H2(t3 + r))
            a1, a2, a3, a4, a5, a6, mu = self.parsedeletenode(deletenode)
    
            # 3b
            self.Ad[int(addr_D)] = os.urandom(6 * self.addr_size + self.k)
            
            # 3c + 3d + 3e
            phi = self.split(self.Ts['free'], self.addr_size)[0]
            self.Ts['free'] = a4 + zerostring
            self.As[int(a4)] = phi + addr_D      # aiprime in paper
            
            # 3f
            self.As[int(a5)] = self.xor(self.As[int(a5)], zerostring + self.xor(a4, a6) + \
                               "\0" * self.k)

            self.Ad[int(a2)] = self.xor(self.Ad[int(a2)], 2 * zerostring + \
                               self.xor(addr_D, a2) + 2 * zerostring + self.xor(a4, a5) + \
                               zerostring + 2 * self.k * "\0")
        
            # 3g
            self.Ad[int(a3)] = self.xor(self.Ad[int(a3)], zerostring + self.xor(addr_D, a2) + \
                               2 * zerostring + self.xor(a4, a5) + zerostring + 2 * self.k * "\0")
        
            addr_D = a1

        idtodelete = self.iddb[id]  # this is a SHA1 hash of the filename. We don't know
                                    # all the filenames, so we let the caller worry about it.
        del self.Td[t1]
        del self.iddb[id]
        return idtodelete

if __name__ == "__main__":
    dsse = DSSEServer(32, 5)
    
    
    
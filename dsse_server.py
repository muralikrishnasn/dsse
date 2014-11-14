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
from Crypto.Cipher import AES

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


    def __init__(self):
        pass

    
    def Search():
        pass
    
    
    def Add():
        pass
    
    
    def Del():
        pass
    
    
if __name__ == "__main__":
    dsse = DSSEServer()
    
    
    
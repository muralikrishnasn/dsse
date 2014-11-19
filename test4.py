#!/usr/bin/python
# -*- coding: utf-8 -*-

import dsse_client
import dsse_server
import pickle

if __name__ == "__main__":
    client = dsse_client.DSSEClient()
    client.importkeys(pickle.load(open("keys", "rb")))
    
    server = dsse_server.DSSEServer()
    client.set_address_size(server.get_address_size())

    print "removing gandhi.txt"
    token1 = client.DelToken("./data/gandhi.txt")
    print server.Del(token1)

    print "searching Margaret"
    token2 = client.SrchToken("Margaret")
    print server.Search(token2)

    print "searching life"
    token3 = client.SrchToken("life")
    print server.Search(token3)
    
    print "searching nonviolence"
    token4 = client.SrchToken("nonviolence")
    print server.Search(token4)

    print "searching glockenspiel"
    token5 = client.SrchToken("glockenspiel")
    print server.Search(token5)

    print "searching luminosity"
    token6 = client.SrchToken("luminosity")
    print server.Search(token6)
    
    
    server.updatedatabases()
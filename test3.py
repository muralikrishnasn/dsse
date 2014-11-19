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

    print "adding lhc.txt"
    token1 = client.AddToken("./data/lhc.txt")
    server.Add(token1, "./data/lhc.txt")

    print "searching life"
    token2 = client.SrchToken("life")
    print server.Search(token2)

    print "searching nonviolence"
    token3 = client.SrchToken("nonviolence")
    print server.Search(token3)

    print "searching glockenspiel"
    token4 = client.SrchToken("glockenspiel")
    print server.Search(token4)

    print "searching luminosity"
    token5 = client.SrchToken("luminosity")
    print server.Search(token5)
    
    
    server.updatedatabases()
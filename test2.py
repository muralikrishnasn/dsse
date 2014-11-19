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

    token1 = client.SrchToken("Margaret")
    print server.Search(token1)
    
    token2 = client.SrchToken("life")
    print server.Search(token2)
    
    token3 = client.SrchToken("nonviolence")
    print server.Search(token3)
    
    token4 = client.SrchToken("glockenspiel")
    print server.Search(token4)
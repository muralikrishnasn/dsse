#!/usr/bin/python
# -*- coding: utf-8 -*-

import dsse_client
import dsse_server
import pickle
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Provide at least one argument, please"
        sys.exit(1)

    client = dsse_client.DSSEClient()
    client.importkeys(pickle.load(open("keys", "rb")))

    server = dsse_server.DSSEServer()
    client.set_address_size(server.get_address_size())

    token = client.SrchToken(sys.argv[1])
    print "Searching for keyword {}: {}".format(sys.argv[1], server.Search(token))
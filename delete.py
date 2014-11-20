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

    print "Removing {} from the server".format(sys.argv[1])
    token = client.DelToken(sys.argv[1])
    ret = server.Del(token)
    if ret is None:
        print "{} was not removed".format(sys.argv[1])
    else:
        print "Removal of {} successful".format(ret)
    
    # We are responsible for writing back changes.
    server.updatedatabases()
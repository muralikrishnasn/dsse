#!/usr/bin/python
# -*- coding: utf-8 -*-

import dsse_client
import pickle
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Provide at least one argument, please"
        sys.exit(1)

    client = dsse_client.DSSEClient()
    client.importkeys(pickle.load(open("keys", "rb")))

    # No checking whatever is performed. For demo purposes only!
    # Enc dumps the DBs when done.
    client.Enc(sys.argv[1:])
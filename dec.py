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

    client.Dec(sys.argv[1])
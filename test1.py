#!/usr/bin/python
# -*- coding: utf-8 -*-

import dsse_client
import pickle

if __name__ == "__main__":
    client = dsse_client.DSSEClient()
    client.Gen()
    client.Enc(["./data/thatcher.txt", "./data/gandhi.txt"])
    pickle.dump(client.exportkeys(), open("keys", "wb"))
#!/usr/bin/python
# -*- coding: utf-8 -*-

import dsse_client
import pickle

if __name__ == "__main__":
    client = dsse_client.DSSEClient()
    client.Gen()
    pickle.dump(client.exportkeys(), open("keys", "wb"))
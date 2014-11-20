# DSSE

Python implementation of Dynamic Searchable Symmetric Cryptography as described by Kamara et al.

dsse_client and dsse_server implement the nine functions outlined in the paper as well as several helper functions to support them. Some simple demo applications are included but are little more than self-contained wrappers for each specific function.

Note that the original paper is vague or incomplete in a few areas, including its description of logic for deleting files on the server side.

This code is considered feature-complete but unstable. No security guarantees are made or implied. Use with caution.

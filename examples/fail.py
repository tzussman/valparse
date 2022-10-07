#!/usr/bin/env python3

# Preliminary error parsing script

import sys

from valparse import Parser

if len(sys.argv) != 2:
    print("Usage: ./fail.py <xml_file>")
    sys.exit(1)

filename = sys.argv[1]
valfile = Parser(filename)

if valfile.signal:
    print(f"Fatal signal observed: {valfile.signal.signame}")
    print("Do not award memory points if SIGABRT or SIGSEGV")
    sys.exit()

if valfile.errcount:
    print(f"{valfile.errcount} errors observed, do not award error points")
else:
    print("No errors observed.")

if valfile.leakcount:
    print(f"f{valfile.leakcount} leaks observed, do not award leak points")
else:
    print("No leaks observed.")

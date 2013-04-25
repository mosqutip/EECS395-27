#!/usr/bin/python2

import clang.cindex
import sys

fname = sys.argv[1]

index = clang.cindex.Index.create()
prsd = index.parse(fname)

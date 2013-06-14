#!/usr/bin/python2

import clang.cindex as c
import sys

i = c.Index.create()
p = i.parse(sys.argv[1])

def recur(node,l=0):
    tabs = ""
    for j in range(l):
        tabs += "\t"
    for i in node.get_children():
        print tabs, i.location, i.displayname, i.kind, ("parent:" + i.semantic_parent.displayname) if i.lexical_parent else ""
        recur(i,l+1)

recur(p.cursor)

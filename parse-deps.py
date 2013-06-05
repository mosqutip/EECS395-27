#!/usr/bin/python2

import clang.cindex as c

i = c.Index.create()
p = i.parse("data-ctrl.cpp")

for c1 in p.cursor.get_children():
    #if c1.kind == c.CursorKind.CXX_METHOD:
    print c1.location, c1.spelling, c1.kind
    for c2 in c1.get_children():
        print "\t", c2.location, c2.displayname, c2.kind
        #if c2.kind == c.CursorKind.COMPOUND_STMT:
        for c3 in c2.get_children():
            print "\t\t", c3.location, c3.displayname, c3.kind
            for c4 in c3.get_children():
                print "\t\t\t", c4.location, c4.displayname, c4.kind
                for c5 in c4.get_children():
                    print "\t\t\t\t", c5.location, c5.displayname, c5.kind
                    for c6 in c5.get_children():
                        print "\t\t\t\t\t", c6.location, c6.displayname, c6.kind

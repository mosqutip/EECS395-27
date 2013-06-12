#!/usr/bin/python
import sys
import hashlib

if (len(sys.argv) != 2):
    print("Wrong number of arguments. Please provide a single input PDG file.")
    sys.exit(0)

nodes = []

def nonblank(f):
    for l in f:
        line = l.rstrip()
        if line:
            yield line

class pdgnode:
    def __init__(self, idval):
        self.idh = hashlib.md5(idval).hexdigest()
        self.name = idval
        self.alias_depend = []
        self.data_depend = []
        self.ctrl_depend = []

    def add_alias_depend(self, node):
        self.alias_depend.append(node)

    def add_ctrl_depend(self, node):
        self.ctrl_depend.append(node)

    def add_data_depend(self, node):
        self.data_depend.append(node)

    def __repr__(self, l=0):
        retstr = ""
        for i in range(l): retstr += "\t"
        retstr += "{ %s : %s\n" % (self.idh, self.name)
        for i in range(l): retstr += "\t"
        for a in self.alias_depend:
            for i in range(l): retstr += "\t"
            retstr += a.__repr__() + "\n"
        for i in range(l): retstr += "\t"
        retstr += "data:\n"
        for d in self.data_depend:
            for i in range(l): retstr += "\t"
            retstr += d.__repr__() + "\n"
        for i in range(l): retstr += "\t"
        retstr += "ctrl:\n"
        for c in self.ctrl_depend:
            for i in range(l): retstr += "\t"
            retstr += c.__repr__() + "\n"
        for i in range(l): retstr += "\t"
        retstr += "}"
        return retstr

fname = sys.argv[1]
cur_node = 0

with open(fname) as infile:
    for line in nonblank(infile):
        elements = line.split()
        if (elements[0] == "[Elem]"):
            nodes.append(pdgnode(elements[1]))
            cur_node = nodes[-1]
        elif (elements[0][2] == 'a'):
            cur_node.add_alias_depend(elements[1])
        elif (elements[0][3] == 'c'):
            cur_node.add_ctrl_depend(elements[1])
        elif (elements[0][4] == 'd'):
            cur_node.add_data_depend(elements[1])
        else:
            continue

    for node in nodes:
        print(node)

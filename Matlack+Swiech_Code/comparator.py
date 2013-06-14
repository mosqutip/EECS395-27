#!/usr/bin/python
import sys
import hashlib

if (len(sys.argv) != 3):
    print("Wrong number of arguments. Please provide two input PDG files.")
    sys.exit(0)

nodes1 = []
nodes2 = []

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
        retstr += "alias:\n"
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
fname2 = sys.argv[2]
cur_node = 0
start = False

with open(fname) as infile:
    for line in nonblank(infile):
        if (line == "[pdg] ====== PDG GRAPH COMPUTED ======"):
            start = True

        if (start == True):
            elements = line.split()
            if (elements[0] == "[Elem]"):
                nodes1.append(pdgnode(elements[1]))
                cur_node = nodes1[-1]
            elif (elements[0][2] == 'a'):
                cur_node.add_alias_depend(elements[1])
            elif (elements[0][3] == 'c'):
                cur_node.add_ctrl_depend(elements[1])
            elif (elements[0][4] == 'd'):
                cur_node.add_data_depend(elements[1])
            else:
                continue

start = False
cur_node = 0

with open(fname2) as infile:
    for line in nonblank(infile):
        if (line == "[pdg] ====== PDG GRAPH COMPUTED ======"):
            start = True

        if (start == True):
            elements = line.split()
            if (elements[0] == "[Elem]"):
                nodes2.append(pdgnode(elements[1]))
                cur_node = nodes2[-1]
            elif (elements[0][2] == 'a'):
                cur_node.add_alias_depend(elements[1])
            elif (elements[0][3] == 'c'):
                cur_node.add_ctrl_depend(elements[1])
            elif (elements[0][4] == 'd'):
                cur_node.add_data_depend(elements[1])
            else:
                continue

for node1 in nodes1:
    for node2 in nodes2:
        if (node1.name == node2.name and node1.alias_depend == node2.alias_depend and
            node1.ctrl_depend == node2.ctrl_depend and node1.data_depend == node2.data_depend):
            print("Match found!\nNode 1: ")
            print(node1)
            print("\nNode 2: ")
            print(node2)

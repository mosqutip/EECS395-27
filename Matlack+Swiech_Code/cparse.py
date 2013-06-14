#!/usr/bin/python
import sys
import hashlib

if len(sys.argv) != 2:
    print("wrong number of args, numbnuts")
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
        self.data_depend = []
        self.ctrl_depend = []

    def add_ctrl_depend(self, node):
        self.ctrl_depend.append(node)

    def add_data_depend(self, node):
        self.data_depend.append(node)

    def __repr__(self, l=0):
        retstr = ""
        for i in range(l): retstr += "\t"
        retstr += "{ %s : %s\n" % (self.idh, self.name)
        for i in range(l): retstr += "\t"
        retstr += "data:\n"
        for d in self.data_depend:
            for i in range(l): retstr += "\t"
            retstr += d.__repr__(l+1) + "\n"
        for i in range(l): retstr += "\t"
        retstr += "ctrl:\n"
        for c in self.ctrl_depend:
            for i in range(l): retstr += "\t"
            retstr += c.__repr__(l+1) + "\n"
        for i in range(l): retstr += "\t"
        retstr += "}"
        return retstr

fname = sys.argv[1]

with open(fname) as infile:
    for line in nonblank(infile):
        print(line)
        if line == "}" or line == "{":
            #print("skipping")
            continue
        nodes.append(pdgnode(line))

    for node in nodes:
        print(node)

#s0 = pdgnode("int jizz;")
#s1 = pdgnode("int ted;")
#s2 = pdgnode("if (ted == jizz)")
#s3 = pdgnode("print(cock)")
#s4 = pdgnode("return ted")

#s2.add_data_depend(s0)
#s2.add_data_depend(s1)
#s4.add_data_depend(s1)
#s3.add_ctrl_depend(s2)

#print(s0)
#print(s1)
#print(s2)
#print(s3)
#print(s4)

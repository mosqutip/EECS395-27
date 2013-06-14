import os
import fnmatch
import re
from MysqlInterface import *

def findSourceFile(root):
	clist = []
	cpplist = []
	hlist = []
	for rootdir, dirnames, filenames in os.walk(root):
		rootdir = rootdir.replace(root + '/' ,'')
		for filename in filenames:
			flag = False;
			if re.match('^[A-Za-z0-9\\s_]*\\.c$', filename):
				clist.append(rootdir + '/' + filename)
				flag = True
			if re.match('^[A-Za-z0-9\\s_]*\\.cpp$', filename):
				cpplist.append(rootdir + '/' + filename)
				flag = True
			if re.match('^[A-Za-z0-9\\s_]*\\.h$', filename):
				hlist.append(rootdir + '/' + filename)
				flag = True
							
	return (clist, cpplist, hlist)

def findDependencies(filename):
	f = open(filename, 'r')
	dep = []
	funcs = []
	for line in f:
		line = line.replace(' ', '');
		# only those  Mozillar libararies, no system libraries
		m = re.match('^#include\"([a-zA-Z0-9_/]*\\.h)\"$',line)
		if m is not None:
			lib = m.group(1)
			lib_name = lib[lib.rfind("/") + 1:len(lib)]	
			dep.append(lib_name)
		
		m = re.search('([a-zA-Z0-9_]*)\(', line)
		if m is not None:
			func = m.group(1)
			if func != 'if' and func != 'while' and func != 'switch' and func != 'for':
				funcs.append(func)

	return (dep,funcs)

def findVulComponents(cvsJason):
	f = open(cvsJason, 'r')
	flist = []
	for line in f:
		#print line
		line = line.replace('\xc2','').replace('\xa0','').replace(' ', '').replace('\t','')
		m = re.match('^\[[0-9]*\]=&gt;([a-zA-Z0-9_/]*\\.(cpp|h|c))(<br>)?$',line)
		if m is not None:
			flist.append(m.group(1))
			print m.group(1)
	return frozenset(flist)

def buildDependencies(flist):
	deps = {}
	funcs = {}
	for f in flist:
		print "Building depency " + f
		dep, func = findDependencies(f)
		deps[f] = dep
		funcs[f] = func
	return (deps, funcs)
	

def storeFilesToDB(files):
	x = Mysql_writer()
	x.connect()
	x.clearHistory()
	for f in files:
		fname = f[f.rfind("/")+1:len(f)]
		print f + " || " + fname
		x.add_file(fname, f)
	x.close()

def storeDepsToDB(deps):
	file2id = {}
	blacklist = {}

	x = Mysql_writer()
	x.connect()
	for f in deps:
		print "Processing file " + f
		row = x.find_file_path(f)
		if len(row) == 0:
			continue
		i = row[0]
		dep_list = deps[f]
		for dep in dep_list:
			print "\tDepend on " + dep
			if blacklist.has_key(dep):
				print "\tIs in blacklist"
				continue
			elif not file2id.has_key(dep):
				js = x.find_file_name(dep)
				if len(js) > 1:
					print "\tMore than one module found for " + dep
					blacklist[dep] = 1
					continue
				elif len(js) == 0:
					print "\tNo module found for " + dep
					blacklist[dep] = 1
					continue
				else:
					file2id[dep] = js[0][0]
			
			j = file2id[dep]
			x.add_dep(i, j)
			print "\t!!!!!!store to db now with id " + str(i) + " and " + str(j) 

	x.close()

def storeVulsToDB(vuls):
	x = Mysql_writer()
	x.connect()
	for path in vuls:
		x.add_vul(path)
	x.close()
						
def main():
	s = findVulComponents('bugs.html')
	storeVulsToDB(s)


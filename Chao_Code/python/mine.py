from MysqlInterface import *
from itertools import combinations, chain

def powerset(iterable, limit):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(min(limit, len(s)) +1))

def minePattern():
	x = Mysql_writer()
	x.connect()
	pc = {}
	for fid in x.find_all_vuls():
		print "vulnerable file id %d" % fid
		deps = x.find_deps(fid)
		ps = powerset(deps, 3)
		for pattern in ps:
			if pc.has_key(pattern):			
				pc[pattern].append(fid)
			else:
				pc[pattern] = [fid] 
	x.close()
	pc = filterPattern(pc)
	return pc

def filterPattern(pc):
	todel = []
	for pattern in pc:
		if len(pc[pattern]) < 15:
			todel.append(pattern)

	for pattern in todel:
		del pc[pattern]

	return pc

def minePatternNonVul():
	x = Mysql_writer()
	x.connect()
	fp = {}
	patterns = x.find_all_patterns()
	nonvuls = x.find_all_nonvuls()
	
	for fid in nonvuls:
		print fid
		deps = x.find_deps(fid)
		for i in range(len(patterns)):
			pattern = patterns[i]
			if pattern.issubset(deps):
				if not fp.has_key(fid):
					fp[fid] = []
				fp[fid].append(i)
			else:
				continue
	return fp

def storePatternToDB(pc):
	x = Mysql_writer()
	x.connect()
	x.add_pattern_list(pc)


def traversePattern(pc):
	count = 0
	for pattern in pc:
		if len(pattern)>1:
			print pattern
			count = count+1
	return count


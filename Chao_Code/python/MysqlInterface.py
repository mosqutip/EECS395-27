import MySQLdb
import sys
import random

class Mysql_writer:
	
	def __init__(self):
		self.con = []

	def connect(self):
		self.con = MySQLdb.connect("localhost","chaoshi","chaoshi","vul")
	
	def clearHistory(self):
		cur = self.con.cursor()
		cur.execute("DELETE FROM files")
		self.con.commit()
		cur.close()
	
	def add_file(self, filename, path):
		cur = self.con.cursor()
		cur.execute("INSERT INTO files (Name, Path) VALUES (%s, %s);", (filename, path))
		self.con.commit()
		cur.close()		

	def find_file_path(self, path):
		cur = self.con.cursor()
		cur.execute("SELECT * FROM files where PATH='%s'", path)
		row = cur.fetchone()
		return row

	def find_file_name(self, name):
		cur = self.con.cursor()
		cur.execute("SELECT * FROM files where NAME='%s'", name)
		rows = cur.fetchall()
		return rows

	def add_dep(self, id1, id2):
		cur = self.con.cursor()
		try:
			cur.execute("INSERT INTO dep VALUES (%d, %d);" % (id1, id2))
			self.con.commit()
		except MySQLdb.Error, e:
			self.con.rollback()
			print "conflict for %d %d " % (id1, id2)
		finally:
			cur.close()
	
	def add_vul(self, path):
		cur = self.con.cursor()
		cur.execute("SELECT * FROM files WHERE PATH='%s'" % path);
		row = cur.fetchone()
		if row is not None:
			fid = row[0]
			try:
				cur.execute("INSERT INTO vuls VALUES(%d);" % fid)
				self.con.commit()
			except MySQLdb.Error, e:
				self.con.rollback()
				print "File not found " + path
			finally:
				cur.close()
				
	def find_all_vuls(self):
		cur = self.con.cursor()
		cur.execute("SELECT id from vuls")
		l = []
		for row in cur.fetchall():
			l.append(row[0])
		
		return frozenset(l)
		
	def find_all_nonvuls(self):
		cur = self.con.cursor()
		cur.execute("SELECT id from nonvul")
		l = []
		for row in cur.fetchall():
			l.append(row[0])
		return frozenset(l)
	
	def find_all_patterns(self):
		cur = self.con.cursor()
		cur.execute("SELECT * from pattern")
		rows = cur.fetchall()
		
		pattern_list = []	
		cur = -1
		for row in rows:
			pid = row[0]
			dep = row[1]
			if pid > cur:
				pattern_list.append(set())
				cur = cur + 1
			pattern_list[len(pattern_list)-1].add(dep)
		
		return pattern_list 

	def find_deps(self, fid):
		cur = self.con.cursor()
		cur.execute("SELECT dep.dependency from dep where dep.id=%d" % fid)
		l = []
		for row in cur.fetchall():
			l.append(row[0])
		return frozenset(l)

	def add_pattern_list(self, pc):
		cur = self.con.cursor()
		i=0
		for pattern in pc:
			print "pattern " + str(i) + " contains " + str(len(pattern)) + " deps and appears in " + str(len(pc[pattern])) + " files" 
			for fid in pc[pattern]:
				print fid
				try:
					cur.execute("INSERT INTO file_pattern VALUES(%d, %d)" %(fid, i))
					self.con.commit()
				except MySQLdb.Error, e:
					self.con.rollback()
			
			for dep in pattern:
				try:
					cur.execute("INSERT INTO pattern VALUES(%d, %d)" %(i, dep))
					self.con.commit()
				except MySQLdb.Error, e:
					self.con.rollback()
			i = i+1	


	def add_nonvul_patterns(self, pc):
		cur = self.con.cursor()
		for fid in pc:
			print fid
			for pattern in pc[fid]:
				try:
					cur.execute("INSERT INTO file_pattern VALUES(%d,%d)" %(fid,pattern))
					self.con.commit()
				except MySQLdb.Error, e:
					self.con.rollback()
			 	
	def load_to_text(self):
		cur = self.con.cursor()
		cur.execute("SELECT * FROM vul_pattern");
		rows = cur.fetchall()
		
		
		f = open('svm_data','w')
		cfid = -1
		count = 0
		pl = []

		for i in range(len(rows)):
			row = rows[i]	
			fid = row[0]
			pid = row[1]

			if fid > cfid and cfid > -1:
				# finish last round
				f.write("+1 ")
				for k in range(723):
					if k in pl:
						f.write("%d:1 " % k)
					#else:
					#	f.write("%d:0 " % k)
				f.write("\n")	
				# begin new round
				cfid = fid
				pl = []
				pl.append(pid)
			elif fid > cfid:
				cfid = fid
				pl = []
				pl.append(pid)
			else:
				pl.append(pid)	
			

		cur.close()
		#f.write("\n")
	
		# second half
		cur = self.con.cursor()
		cur.execute("SELECT * FROM nonvul_pattern");
		rows = cur.fetchall()
		
		cfid = -1
		pl = []
		for i in range(len(rows)):
			row = rows[i]
			fid = row[0]
			pid = row[1]
				
			if fid > cfid and cfid > -1:
				f.write("-1 ")
				for k in range(723):
					if k in pl:
						f.write("%d:1 " % k)
					#else:
					#	f.write("%d:0 " % k)
				f.write("\n")
				cfid = fid
				pl = []
				pl.append(pid) 
			
			elif fid > cfid:
				cfid = fid
				pl = []
				pl.append(pid)
			else:
				pl.append(pid)

		cur.close()
		f.close()
		print count
		
	def close(self):
		self.con.close()
	

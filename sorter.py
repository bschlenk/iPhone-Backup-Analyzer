#!/usr/bin/python

import os, sys
import re
import getopt

def get_lines(f_name, cols=16):
	with open(f_name) as f:
		data = f.read()

	matcher = re.compile('^%s$' % '\\|'.join(['(.*?)'] * cols), re.M)
	#matcher = re.compile(r'^(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*)$', re.M)
	print matcher.pattern
	matches = matcher.findall(data)

	matches = sorted([tuple(m) for m in matches], key=lambda x: (x[-7].lower(), x[-6].lower(), x[-5].lower(), x[-4].lower(), x[-8].lower()))
	return matches


'''
CREATE TABLE indice (
0: id INTEGER PRIMARY KEY AUTOINCREMENT,
1: type VARCHAR(1),
2: permissions VARCHAR(9),
3: userid VARCHAR(8),
4: groupid VARCHAR(8),
5: filelen INT,
6: mtime INT,
7: atime INT,
8: ctime INT,
9: fileid VARCHAR(50),
10: domain_type VARCHAR(100),
11: domain VARCHAR(100),
12: file_path VARCHAR(100),
13: file_name VARCHAR(100),
14: link_target VARCHAR(100),
15: datahash VARCHAR(100),
16: flag VARCHAR(100)
)
'''


def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'c:')
	except getopt.GetoptError as err:
		print str(err)
		sys.exit(2)

	cols = 16
	for o, a in opts:
		if o == '-c':
			try:
				cols = int(a)
			except ValueError:
				print 'argument to -c must be in integer'
				sys.exit(2)

	if len(args) != 1:
		print 'usage: %s <file>' % sys.argv[0]
		sys.exit(2)

	print cols
	print args[0]
	lines = get_lines(args[0], cols)
	for l in lines:
		print l
	

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print '\nexiting...'


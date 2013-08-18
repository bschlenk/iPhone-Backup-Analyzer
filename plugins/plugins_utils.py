#!/usr/bin/env python

'''
 Analyzer for iPhone backup made by Apple iTunes

 (C)opyright 2011 Mario Piccinelli <mario.piccinelli@gmail.com>
 Released under MIT licence
 
'''

# IMPORTS -----------------------------------------------------------------------------------------

import sqlite3

# MAIN FUNCTION --------------------------------------------------------------------------------

def realFileName(cursor, filename="", domaintype="", path=""):
	query = "SELECT fileid FROM indice" # WHERE 1=1"

	'''if (filename != ""):
		query = query + " AND file_name = \"%s\""%filename
	if (domaintype != ""):
		query = query + " AND domain_type = \"%s\""%domaintype
	if (path != ""):
		query = query + "AND file_path = \"%s\""%path
	'''

	fields = ['file_name', 'domain_type', 'file_path']
	where_clause = ' AND '.join('%s = "%s"' % (k, v) for k, v in zip(fields, (filename, domaintype, path)) if v)
	if where_clause:
		query = ' WHERE '.join([query, where_clause])

	cursor.execute(query);
	result = cursor.fetchone()
			
	if result:
		return result[0]
	else:
		print("ERROR: could not find file")
		return ""	

# ------------------------------------------------------------------------------------------------------------------------

# reads a DICT node and returns a python dictionary with key-value pairs
def readDict(dictNode):
	ritorno = {}
	
	# check if it really is a dict node
	if (dictNode.localName != "dict"):
		print("Node under test is not a dict (it is more likely a \"%s\")."%node.localName)
		return ritorno
	
	nodeKey = None
	for node in dictNode.childNodes:
		if (node.nodeType == node.TEXT_NODE):
			continue
		
		if (nodeKey is None):
			nodeKeyElement = node.firstChild
			if (nodeKeyElement is None):
				nodeKey = "-"
			else:
				nodeKey = node.firstChild.toxml()
		else:
			ritorno[nodeKey] = node
			nodeKey = None
	
	return ritorno

# ------------------------------------------------------------------------------------------------------------------------

# reads an ARRAY node and returns a python list with elements
def readArray(arrayNode):
	ritorno = []
	
	# check if it really is a dict node
	if (arrayNode.localName != "array"):
		print("Node under test is not an array (it is more likely a \"%s\")."%node.localName)
		return ritorno
	
	for node in arrayNode.childNodes:
		if (node.nodeType == node.TEXT_NODE): continue
		ritorno.append(node)
	
	return ritorno

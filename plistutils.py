#!/usr/bin/env python

'''
 Analyzer for iPhone backup made by Apple iTunes

 (C)opyright 2011 Mario Piccinelli <mario.piccinelli@gmail.com>
 Released under MIT licence

 plistutils.plist provides general functions to deal with plist files
 converted into xml format

'''

import os, sys, subprocess

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
		if (node.nodeType == node.TEXT_NODE): continue
		
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

# ------------------------------------------------------------------------------------------------------------------------

# reads a binary plist file and returns the content in clear text format
def readPlist(filename):
	
	retstring = ""
	
	tempfile = os.path.dirname(sys.argv[0]) + "/out.plist" #default name from perl script plutil.pl
	command = "perl \"" + os.path.dirname(sys.argv[0]) + "/IPBAplutil.pl\" \"%s\" "%filename
	
	#TODO: should this be called twice?
	os.system(command)

	try:
		retval = os.system(command)	
	except:
		print "Unexpected error while running command: \"%s\""%command, sys.exc_info()[1]
		return ""
	
	if (retval != 0):
		print("Return value not clear. Unable to decode data.")
		return ""

	with open(tempfile, 'rb') as fh:
		line = fh.readline()
		retstring = ""
		while line:
			retstring += line
			line = fh.readline()
				
	os.remove(tempfile)
	
	return retstring

# ------------------------------------------------------------------------------------------------------------------------

# reads a binary plist file and returns the content in xml.dom.minidom object
def readPlistToXml(filename):

	tempfile = os.path.dirname(sys.argv[0]) + "/out.plist" #default name from perl script plutil.pl
	command = "perl \"" + os.path.dirname(sys.argv[0]) + "/IPBAplutil.pl\" \"%s\" "%filename

	try:
		retval = os.system(command)	
	except:
		print "Unexpected error while running command: \"%s\""%command, sys.exc_info()[1]
		return None
	
	if (retval != 0):
		print("Return value not clear. Unable to decode data.")
		return None
	
	from xml.dom.minidom import parse
	try:
		xmldata = parse(tempfile)
	except:
		print "Unexpected error while parsing XML data:", sys.exc_info()[1]
		return None
	
	os.remove(tempfile)
	
	return xmldata	

# ------------------------------------------------------------------------------------------------------------------------

# read backup properties from passed file (Info.plist)

def deviceInfo(filename):

	from xml.dom.minidom import parse
	try:
		manifest = parse(filename)
	except:
		print("There was an error while parsing Manifest.plist.")
		return {}

	# <plist>
	document = manifest.getElementsByTagName("plist")
	# main <dict>
	basedict = document[0].childNodes[1]
	
	data = readDict(basedict)

	proplist = (
		"Device Name",
		"Display Name",
		"GUID",
		"ICCID",
		"IMEI",
		"Last Backup Date",
		"Product Type",
		"Product Version",
		"Serial Number",
		"iTunes Version",
		"Unique Identifier"		
	)	
	
	properties = {}
	
	for key in data:
		if (key in proplist):
			properties[key] = data[key].firstChild.toxml()

	return properties

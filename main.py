#!/usr/bin/env python

'''
 Analyzer for iPhone backup made by Apple iTunes

 (C)opyright 2011 Mario Piccinelli <mario.piccinelli@gmail.com>
 Released under MIT licence
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.

'''

# GENERIC IMPORTS --------------------------------------------------------------------------------------

# sqlite3 support library
import sqlite3
# system libraries
import sys, os
# graphic libraries
from Tkinter import *
import Tkinter, ttk
import tkFileDialog, tkMessageBox
# datetime used to convert unix timestamps
from datetime import datetime
# hashlib used to build md5s ans sha1s of files
import hashlib
# binascci used to try to convert binary data in ASCII
import binascii
# getopt used to parse command line options
import getopt
# time used to read system date and time of files
import time
# Python Image Library: graphics and EXIF data from JPG images
from PIL import Image, ImageTk
from PIL.ExifTags import TAGS
# String IO to pass data dumps from databases directly to PIL
import StringIO	
# decode base64 encoded text
import base64
# string functions
import string
# to open external file viewers
import subprocess

# APPLICATION FILES IMPORTS -------------------------------------------------------------------------

# magic.py - identify file type using magic numbers
import magic
# mbdbdecoding.py - functions to decode iPhone backup manifest files
import mbdbdecoding
# plistutils.py - generic functions to handle plist files
import plistutils
# manifestmbdb.py - handlees the decoding of the manifest.mbdb file, as well as 
#                   the creation of a database for convienient searching
import manifestmbdb as MBDB

# GLOBALS -------------------------------------------------------------------------------------------

# version
version = '1.5'
creation_date = 'Feb. 2012'

# set this path from command line
backup_path = '' 

# saves references to images in textarea
# (to keep them alive after callback end)
photoImages = []

# limits the display of rows dumped from a table
rowsoffset = 0
rowsnumber = 100

# set SMALLMONITOR to 1 to modify main UI for small monitors
# (such as a 7' Asus eeepc)
smallmonitor = False

# global font configuration
normalglobalfont = ('Times', 12, 'normal')
smallglobalfont = ('Times', 8, 'normal')
globalfont=normalglobalfont

# iOS version
# 4 - iOS 4
# 5 - iOS 5
#   - does not decode manifest.mbdx (which doesn't exist anymore)
#   - instead find real file name by SHA1ing the string "domain-filename"  
iOSVersion = 5

# FUNCTIONS -------------------------------------------------------------------------------------------

def printEncode(msg):
	print msg.encode(sys.stdout.encoding, 'replace')

def substWith(text, subst = '-'):
	return text if text else subst

def autoscroll(sbar, first, last):
    """Hide and show scrollbar as needed."""
    first, last = float(first), float(last)
    if first <= 0 and last >= 1:
        sbar.grid_remove()
    else:
        sbar.grid()
    sbar.set(first, last)
	
def md5(md5fileName, excludeLine='', includeLine=''):
	"""Compute md5 hash of the specified file"""
	m = hashlib.md5()
	try:
		fd = open(md5fileName,'rb')
	except IOError:
		return '<none>'
	content = fd.readlines()
	fd.close()
	for eachLine in content:
		if excludeLine and eachLine.startswith(excludeLine):
			continue
		m.update(eachLine)
	m.update(includeLine)
	return m.hexdigest()

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length=8, limit=10000):
	N=0
	result=''
	while src:
		s,src = src[:length],src[length:]
		hexa = ' '.join(['%02X' % ord(x) for x in s])
		s = s.translate(FILTER)
		result += '%04X   %-*s   %s\n' % (N, length*3, hexa, s)
		N += length
		if (len(result) > limit):
			src = '';
			result += '(analysis limit reached after %i bytes)' % limit
	return result

def hex2string(src, length=8):
	N=0
	result=''
	while src:
		s,src = src[:length],src[length:]
		hexa = ' '.join(['%02X' % ord(x) for x in s])
		s = s.translate(FILTER)
		N += length
		result += s
	return result	

def hex2nums(src, length=8):
	N = 0
	result = []
	while src:
		s,src = src[:length],src[length:]
		hexa = ' '.join(['%02X' % ord(x) for x in s])
		s = s.translate(FILTER)
		N += length
		result.append(hexa)
	return ' '.join(result)
    
def log(text):
	logbox.insert(END, "\n%s"%text)
	logbox.yview(END)
	
def maintext(text):
	textarea.insert(END, "%s"%text)

def clearmaintext():
	textarea.delete(1.0, END)
	
# scans the main tree view and returns the code of the node with a specified ID
# (by the way, the ID is the index of the element in the index database)
def searchIndexInTree(index, parent=''):
	#print("---- searching under node: %s"%(tree.item(parent)['text']))
	for node in tree.get_children(parent):			
		#print("node under exam: %s - %s"%(node,tree.item(node)['text']))
		id = tree.set(node, 'id')
		#print("Confronto id %s con %s"%(id, index))
		if (id):
			if (int(id) == int(index)): 
				#print("found!")
				return node			
		sottonodi = searchIndexInTree(index, node)
		if (sottonodi is not None):
			return sottonodi	
	return
	
# Called when a button is clicked in the buttonbox (upper right) -----------------------------------------

# open selected file in OS viewer
fileNameForViewer = ''
def openFile(event):
	global fileNameForViewer
	
	if (fileNameForViewer):
	
		answer = tkMessageBox.askyesno('Caution',
			'Are you sure you want to open the selected file with an external viewer? This could modify the evidence!',
			icon='warning', default='no'
		)

		if (answer):
			print('Opening with viewer: %s' % fileNameForViewer)
			
			# mac os specific
			if sys.platform.startswith('darwin'):
				log('Opening with Mac Os "open" the file: %s' % (fileNameForViewer, ))
				subprocess.call(['open', fileNameForViewer], shell=False)
			
			# linux specific
			elif sys.platform.startswith('linux'):
				log('Opening with Linux "gnome-open" the file: %s' % (fileNameForViewer,))
				subprocess.call(['gnome-open', fileNameForViewer], shell=False)
			
			# windows specific
			elif sys.platform.startswith('win'):
				log('Opening with Windows "start" the file: %s' % (fileNameForViewer))
				subprocess.call(['start', fileNameForViewer])
			
			# other
			else:
				log('This platform doesn\'t support this function.')

# search function globals
pattern = ''
searchindex = '1.0'

def buttonBoxPress(event):		
	
	# SEARCH button
	
	if (event.widget['text'] == 'Search'):
		
		global pattern
		global searchindex
		
		if (pattern != searchbox.get(1.0, END).strip() or not searchindex):
			searchindex = "1.0";
		
		pattern = searchbox.get("1.0", END).strip()
		if (not str(pattern)): return
		
		textarea.mark_set("searchLimit", textarea.index("end"))
		
		searchindex = textarea.search(pattern, "%s+1c" % (searchindex) , "searchLimit", regexp=True, nocase=True)
		if not searchindex:
			return
		
		textarea.tag_delete("yellow")
		textarea.tag_configure("yellow",background="#FFFF00")
		textarea.tag_add("yellow", searchindex, "%s+%sc" % (searchindex, str(len(pattern))))
		
		textarea.mark_set("current", searchindex)
		textarea.yview(searchindex)
	
# WRITE TEXT TO FILE button

def writeTXT(): 

	outfile = tkFileDialog.asksaveasfile(mode='w', parent=root, initialdir='/home/', title='Select output text file')
	if (outfile):
		text = textarea.get("1.0", END)
		outfile.write(text)
		tkMessageBox.showwarning("Done", "Text saved\n")
		outfile.close()
	else:
		log("Write Txt operation cancelled")
		#tkMessageBox.showwarning("Error", "Text NOT saved\n")


# Called when the "convert from unix timestamp" button is clicked  ------------------------------------

def convertTimeStamp(event):
	timestamp = timebox.get("1.0", END)
	if (not timestamp.strip()):
		return
	
	try:
		timestamp = int(timestamp)
	# TODO: except specific exception
	except:
		timebox.config(background="IndianRed1")
		return
	
	timestamp += 978307200 #JAN 1 1970
	convtimestamp = datetime.fromtimestamp(timestamp)
	timebox.delete("1.0", END)
	timebox.insert("1.0", convtimestamp)

def clearTimeBox(event):
	timebox.config(background="white")
	
# MAIN ----------------------------------------------------------------------------------------------------

if __name__ == '__main__':

	# we have to create immediately the root window, to be able to use tkFileDialog
	# for now we withdraw it.. we will show it again at the end of the UI building
	root = Tkinter.Tk()
	root.title('iPhone Backup analyzer')
	root.withdraw()

	def banner():
		print('\niPBA - iPhone backup analyzer v. %s (%s)' % (version, creation_date))
		print('Released by <mario.piccinelli@gmail.com> under MIT licence')

	# usage
	def usage():
		banner()
		print('''
 -h              : this help
 -d <dir>        : backup dir
 -s              : adapt main UI for small monitors (such as 7')
 -q <file>       : the name of the database file. if not specified, :memory: is used
         iOS Version <= 4 not currently suppoted 
''')

	# input parameters
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'hd:sq:')
	except getopt.GetoptError as err:
		usage()
		print('\n%s\n' % str(err))
		sys.exit(2)
	
	database_file = ':memory:'
	for o, a in opts:
		if o in ("-h"):
			usage()
			sys.exit(0)
		
		if o in ("-d"):
			backup_path = a
			if (backup_path.strip()[-1] != "/"):
				backup_path = backup_path + "/"
		
		if o in ("-s"):
			smallmonitor = True
			globalfont = smallglobalfont

		if o in ('-q'):
			database_file = a
		

	# show window to select directory
	if (not backup_path):
		backup_path = tkFileDialog.askdirectory(mustexist=True, title="Select backup path")

	# chech existence of backup dir
	if (not os.path.isdir(backup_path)):
		usage()
		print('\nThe provided backup dir "%s" is not a valid folder.\n' % backup_path)
		sys.exit(1)

	# decode Manifest files
	mbdbPath = os.path.join(backup_path, 'Manifest.mbdb')
	try:
		mbdb = MBDB.ManifestMBDB(mbdbPath, db_file=database_file)
	except MBDB.ManifestMBDBError as e:
		usage()
		print('%s - are you sure this is a correct iOS backup dir?\n' % e)
		sys.exit(1)
	
	banner()
	print("\nWorking directory: %s" % backup_path)
	print("Read elements: %i" % len(mbdb))
	
	# Builds user interface ----------------------------------------------------------------------------------
	
	# root window
	#root = Tkinter.Tk()
	root.configure(background='#4d66fa')
	root.geometry("%dx%d%+d%+d" % (1200, 700, 0, 0))
	root.grid_columnconfigure(2, weight=1)
	root.grid_rowconfigure(1, weight=1)

	# left column
	leftcol = Frame(root, relief=RAISED, bd=2, bg='lightblue');
	leftcol.grid(column = 0, row = 1, sticky="nsew", padx=5, pady=5)
	leftcol.grid_columnconfigure(0, weight=1)
	leftcol.grid_rowconfigure(3, weight=1)
	
	# scrollbars for main tree view
	vsb = ttk.Scrollbar(leftcol, orient="vertical")
	hsb = ttk.Scrollbar(leftcol, orient="horizontal")
	  
	# main tree view definition
	w = Label(leftcol, text="Backup content:", font=globalfont, bg='lightblue')
	w.grid(column=0, row=2, sticky='ew')
	tree = ttk.Treeview(leftcol, columns=("type", "size", "id"),
	    displaycolumns=("size"), selectmode='browse',
		yscrollcommand=lambda f, l: autoscroll(vsb, f, l),
	    xscrollcommand=lambda f, l:autoscroll(hsb, f, l))
	tree.heading("#0", text="Element description", anchor='w')
	tree.heading("size", text="File Size", anchor='w')
	
	if (smallmonitor):
		tree.column("#0", width=200)
		tree.column("size", width=30)
	else:
		tree.column("#0", width=250)
		tree.column("size", width=50)	
	
	vsb['command'] = tree.yview
	hsb['command'] = tree.xview
	tree.grid(column=0, row=3, sticky='nswe', padx=3, pady=3)
	vsb.grid(column=1, row=3, sticky='ns')
	hsb.grid(column=0, row=4, sticky='ew')
	
	# device info box
	w = Label(leftcol, text="Backup info:", font=globalfont, bg='lightblue')
	w.grid(column=0, row=0, sticky='ew', columnspan=2)
	infobox = Text(
		leftcol, 
		relief="sunken", 
		borderwidth=2, 
		height=15, 
		width=20, 
		font=globalfont, 
		highlightbackground='lightblue'
	)
	infobox.grid(column=0, row=1, sticky='ew', padx=3, pady=3, columnspan=2)
	
	# right column
	buttonbox = Frame(root, bd=2, relief=RAISED, bg='lightblue');
	buttonbox.grid(column = 4, row = 1, sticky="ns", padx=5, pady=5)
	
	w = Label(buttonbox, text="Text search", font=globalfont, bg='lightblue')
	w.pack()
	
	searchbox = Text(
		buttonbox, 
		width=20, 
		height=1, 
		relief="sunken", 
		borderwidth=2, 
		font=globalfont, 
		highlightbackground='lightblue'
	)
	searchbox.pack()
	
	w = Button(
		buttonbox, 
		text="Search", 
		width=10, 
		default=ACTIVE, 
		font=globalfont, 
		highlightbackground='lightblue'
	)
	w.bind("<Button-1>", buttonBoxPress)
	w.pack()

	w = Label(buttonbox, text="Timestamp translation", font=globalfont, bg='lightblue')
	w.pack()
	
	timebox = Text(
		buttonbox, 
		width=20, 
		height=1, 
		relief="sunken", 
		borderwidth=2, 
		font=globalfont,
		highlightbackground='lightblue'
	)
	timebox.pack()
	
	w = Button(
		buttonbox, 
		text="Convert", 
		width=10, 
		default=ACTIVE, 
		font=globalfont, 
		highlightbackground='lightblue'
	)
	w.bind("<Button-1>", convertTimeStamp)
	w.pack()
	
	w = Button(
		buttonbox, 
		text="Open reader", 
		width=10, 
		default=ACTIVE, 
		font=globalfont, 
		highlightbackground='lightblue'
	)
	w.bind("<Button-1>", openFile)
	w.pack()

	# tables tree (in right column)
	w = Label(buttonbox, text="Database tables", font=globalfont, bg='lightblue')
	w.pack()
	
	tablestree = ttk.Treeview(buttonbox, columns=("filename", "tablename"), displaycolumns=())			
	tablestree.heading("#0", text="Tables")
	
	if (smallmonitor):
		tablestree.column("#0", width=150)
	else:
		tablestree.column("#0", width=200)
	
	tablestree.pack(fill=BOTH, expand=1, padx=3, pady=3)
	
	# log row
	logbox = Text(
		root, 
		relief="sunken", 
		borderwidth=2, 
		height=3, 
		bg='lightblue', 
		font=globalfont,
		highlightbackground='#4d66fa'
	)
	logbox.grid(row=4, columnspan=6, sticky='ew')
	
	# header row
	headerbox = Frame(root, bd=2, relief=RAISED, bg='lightblue');
	icon_path = os.path.join(os.path.dirname(__file__), "iphone_icon.png")

	im = Image.open(icon_path)
	photo = ImageTk.PhotoImage(im)	
	w = Label(headerbox, image=photo, bg='lightblue')
	w.photo = photo
	w.pack(side=LEFT)	
	
	im = Image.open(icon_path)
	photo = ImageTk.PhotoImage(im)	
	w = Label(headerbox, image=photo, bg='lightblue')
	w.photo = photo
	w.pack(side=RIGHT)
	
	w = Label(
		headerbox, 
		text="iPBA - iPhone Backup Analyzer\nVersion: %s (%s)"%(version, creation_date), 
		font=globalfont, 
		bg='lightblue'
	)
	w.pack()
	
	headerbox.grid(column=0, row=0, sticky='ew', columnspan=6, padx=5, pady=5)

	# notebook (alternative to the definition of a simple centercolumn)
	
	nbstyle = ttk.Style()
	nbstyle.configure("My.TNotebook", padding=0)
	
	notebook = ttk.Notebook(root, style="My.TNotebook")
	# main text area
	centercolumn = ttk.Frame(notebook);
	notebook.add(centercolumn, text='Description')
	# preview for images
	previewcolumn = ttk.Frame(notebook);
	notebook.add(previewcolumn, text='Preview')
	notebook.hide(previewcolumn)
	# exif tab for images
	exifcolumn = ttk.Frame(notebook);
	exifcolumn_label = Text(
		exifcolumn, 
	    bd=2, 
	    relief=SUNKEN, 
	    font=globalfont, 
	    highlightbackground='lightblue'
	)
	exifcolumn_label.grid(column=0, row=0, sticky="nsew")
	exifcolumn.grid_columnconfigure(0, weight=1)
	exifcolumn.grid_rowconfigure(0, weight=1)
	notebook.add(exifcolumn, text='EXIF data')
	notebook.hide(exifcolumn)
		
	notebook.grid(column = 2, row = 1, sticky="nsew")

	# center column (substituted by notebook)
	#centercolumn = Frame(root, bd=2, relief=RAISED);
	#centercolumn.grid(column = 2, row = 1, sticky="nsew")
	centercolumn.grid_columnconfigure(0, weight=1)
	centercolumn.grid_rowconfigure(0, weight=1)

	# main textarea
	textarea = Text(
		centercolumn, 
		yscrollcommand=lambda f, l: autoscroll(tvsb, f, l),
	    bd=2, 
	    relief=SUNKEN, 
	    font=globalfont, 
	    highlightbackground='lightblue'
	)
	textarea.grid(column=0, row=0, sticky="nsew")

	# scrollbars for main textarea
	tvsb = ttk.Scrollbar(centercolumn, orient="vertical")
	tvsb.grid(column=1, row=0, sticky='ns')
	tvsb['command'] = textarea.yview
	
	# block for selecting limit for browsing table fields
	tableblock = Frame(centercolumn, bd=2, relief=RAISED, bg='#4d66fa');
	tableblock.grid(column = 0, row = 1, sticky="nsew")	
	tableblock.grid_columnconfigure(1, weight=1)

	def recordlabelupdate():
		global rowsoffset, rowsnumber
		fieldlabeltext.set("Showing records from %i to %i."%(rowsoffset*rowsnumber, (rowsoffset+1)*rowsnumber-1));
	
	def recordplusbutton(event):
		global rowsoffset
		rowsoffset += 1
		recordlabelupdate()
		TablesTreeClick(None)

	def recordlessbutton(event):
		global rowsoffset
		rowsoffset -= 1
		if (rowsoffset < 0): rowsoffset = 0
		recordlabelupdate()
		TablesTreeClick(None)

	fieldless = Button(
		tableblock, 
		text="<", 
		width=10, 
		default=ACTIVE, 
		font=globalfont,
		highlightbackground='#4d66fa'
	)
	fieldless.bind("<Button-1>", recordlessbutton)
	fieldless.grid(column=0, row=0, sticky="nsew")

	fieldlabeltext = StringVar()
	fieldlabel = Label(tableblock, textvariable=fieldlabeltext, relief=RIDGE, font=globalfont)
	fieldlabel.grid(column=1, row=0, sticky='nsew', padx=3, pady=3)
	recordlabelupdate()

	fieldplus = Button(
		tableblock, 
		text='>', 
		width=10, 
		default=ACTIVE, 
		font=globalfont,
		highlightbackground='#4d66fa'
	)
	fieldplus.bind('<Button-1>', recordplusbutton)
	fieldplus.grid(column=2, row=0, sticky='nsew')

	# menu --------------------------------------------------------------------------------------------------
	
	def aboutBox():
		aboutTitle = "iPBA iPhone Backup Analyzer"
		aboutText = '\n'.join([
			"(c) Mario Piccinelli 2011 <mario.piccinelli@gmail.com>",
			" Released under MIT Licence",
			" Version: %s" % version,
		])
		tkMessageBox.showinfo(aboutTitle, aboutText)
	
	def quitMenu():
		exit(0)
			
	def placesMenu(filename, filepath=None):
		if not filename:
			return

		file_id = mbdb.fileId(filename, filepath)
		if not file_id:
			log('File %s not found.' % filename)
			return
		
		nodeFound = searchIndexInTree(file_id)
		
		if nodeFound is None:
			log(u'Node not found in tree while searching for file %s (id %s).' % (filename, file_id))
			return
			
		tree.see(nodeFound)
		tree.selection_set(nodeFound)
		OnClick() #triggers refresh of main text area
	
	def base64dec():	
		try:
			enctext = textarea.get(SEL_FIRST, SEL_LAST)
		except TclError:
			tkMessageBox.showwarning("Decode Base64", "Please select some text in the main window")
			return
		
		clearenctext = ''.join(ch for ch in enctext if ch not in string.whitespace)
		padding = 4 - len(clearenctext) % 4
		if padding:
			clearenctext += "=" * padding
		log(clearenctext)
		
		try:
			dectext = base64.b64decode(clearenctext)		
			decstring = ''.join(ch for ch in dectext if ch in string.printable)
			tkMessageBox.showinfo("Decoded Base64 data", decstring)
		except TypeError as e:
			log(str(e))
			tkMessageBox.showwarning("Error", "Unable to decode selected data.\nMaybe you didn't select the whole data, or the selected data is not encoded in Base64?")

	# Menu Bar
	menubar = Menu(root)
	
	# Places menu
	placesmenu = Menu(menubar, tearoff=0)

	placesmenu.add_command(
		label="Address Book", 
		command=lambda:placesMenu(filename="AddressBook.sqlitedb")
	)
	placesmenu.add_command(
		label="Address Book Images", 
		command=lambda:placesMenu(filename="AddressBookImages.sqlitedb")
	)
	placesmenu.add_command(
		label="Calendar", 
		command=lambda:placesMenu(filename="Calendar.sqlitedb")
	)
	placesmenu.add_command(
		label="Notes", 
		command=lambda:placesMenu(filename="notes.sqlite")
	)
	placesmenu.add_command(
		label="SMS", 
		command=lambda:placesMenu(filename="sms.db")
	)
	placesmenu.add_command(
		label="Safari Bookmarks", 
		command=lambda:placesMenu(filename="Bookmarks.db")
	)
	placesmenu.add_command(
		label="Safari History", 
		command=lambda:placesMenu(filename="History.plist", filepath='Library/Safari')
	)

	placesmenu.add_separator()
	placesmenu.add_command(label="Write Txt", command=writeTXT)
	placesmenu.add_command(label="Decode Base64", command=base64dec)
		
	menubar.add_cascade(label="Places", menu=placesmenu)
	
	# Windows menu
	winmenu = Menu(menubar, tearoff=0)
	
	print("\n**** Loading plugins...")
	
	pluginsdir = os.path.join(os.path.dirname(__file__), "plugins")
	print("Loading plugins from dir: %s" % pluginsdir)
	
	def getFunc(m_name):
		def func():
			getattr(sys.modules[m_name], 'main')(mbdb, backup_path)
		return func

	for module in os.listdir(pluginsdir):
		if module == '__init__.py' or not module.endswith('.py') or module == 'plugins_utils.py':
			continue
		modname = '.'.join(['plugins', os.path.splitext(module)[0]])
		
		# check whether module can be imported
		try:
			__import__(modname)
		except:
			print("Error while trying to load plugin file: %s" % modname)
			print sys.exc_info()[0]
			continue
		
		# check whether module has main() method
		try:
			getattr(sys.modules[modname], "main")
		except:
			print("Error: main() method not found in plugin %s" % modname)
			continue	
		
		# check whether module has PLUGIN_NAME() method (optional)
		try:
			moddescr = getattr(sys.modules[modname], "PLUGIN_NAME")
			print("Loaded plugin: %s - %s" % (modname, moddescr))
		except:
			print("Loaded plugin: %s - (name not available)" % modname)
			moddescr = modname

		winmenu.add_command(
			label=moddescr, 
			command=getFunc(modname)
		)		
	
	menubar.add_cascade(label="Plugins", menu=winmenu)
	
	# ABOUT menu
	helpmenu = Menu(menubar, tearoff=0)
	helpmenu.add_command(label="About", command=aboutBox)
	helpmenu.add_separator()
	helpmenu.add_command(label="Quit", command=quitMenu)
	menubar.add_cascade(label="Help", menu=helpmenu)
	
	# display the menu
	root.config(menu=menubar)
	
	# populate the main tree frame ----------------------------------------------------------------------------
	
	# standard files
	
	tree.tag_configure('base', font=globalfont)
		
	base_files_index = tree.insert('', 'end', text="Standard files", tag='base')
	tree.insert(base_files_index, 'end', text="Manifest.plist", values=("X", "", 0), tag='base')
	tree.insert(base_files_index, 'end', text="Info.plist", values=("X", "", 0), tag='base')
	tree.insert(base_files_index, 'end', text="Status.plist", values=("X", "", 0), tag='base')
	
	domain_types = mbdb.domainTypes()

	print("\nBuilding UI..")
	
	# building the file hierarchy
	for domain_type in domain_types:
		domain_type_index = tree.insert('', 'end', text=domain_type, tag='base')
		print(u'Listing elements for domain family: %s' % domain_type)
		
		domain_names = mbdb.domainTypeMembers(domain_type)
		
		for domain_name in domain_names:
			domain_name_index = domain_type_index
			if domain_name:
				domain_name_index = tree.insert(domain_type_index, 'end', text=domain_name, tag='base')
			
			paths = mbdb.filePathsOfDomain(domain_type, domain_name)
			
			file_path_map = {} # store name, treeindex pairs

			for path in paths:
				path_index = file_path_map.get(path, domain_name_index)
				if path_index == domain_name_index:
					if path:
						path_index = tree.insert(domain_name_index, 'end', text=path, tag='base')
				
				files = mbdb.filesInDir(domain_type, domain_name, path)
				
				for f in files:
					file_name = f['file_name']
					file_len  = f['filelen']
					file_id   = f['id']
					file_type = f['type']

					if (file_len) < 1024:
						file_dim = unicode(file_len) + u' B'
					else:
						file_dim = unicode(file_len / 1024) + u' KiB'

					if file_name:
						file_index = tree.insert(path_index, 'end', text=file_name, values=(file_type, file_dim, file_id), tag='base')
						if file_type == u'd':
							file_path_map[os.path.join(path, file_name)] = file_index
					else:
						tree.item(path_index, values=(file_type, file_dim, file_id))

			
	print(u'Construction complete.\n')
	
	# Now that the UI has been built, we cancel the "withdraw" operation done before
	# and show the main window
	root.deiconify()

	# called when an element is clicked in the tables tree frame ------------------------------------------------
	
	def TablesTreeClick(event):
	
		global rowsoffset, rowsnumber
		
		if (event is not None): 
			rowsoffset = 0
			recordlabelupdate()

		if (not tablestree.selection()): return;
		
		seltable = tablestree.selection()[0]
		seltable_dbname = tablestree.set(seltable, 'filename')
		seltable_tablename = tablestree.set(seltable, 'tablename')
		
		# clears main text field
		clearmaintext()
				
		# table informations
		maintext(u'Dumping table: %s\nFrom file: %s' % (seltable_tablename, seltable_dbname))
		log(u'Dumping table %s from database %s.' % (seltable_tablename, seltable_dbname))
		
		if (os.path.exists(seltable_dbname)):
			seltabledb = sqlite3.connect(seltable_dbname)
			try:
				seltablecur = seltabledb.cursor() 
				
				# read selected table indexes
				seltablecur.execute(u'PRAGMA table_info(%s)' % seltable_tablename)
				seltable_fields = seltablecur.fetchall();
				
				# append table fields to main textares
				seltable_fieldslist = []
				maintext(u'\n\nTable Fields:')
				for seltable_field in seltable_fields:
					maintext(u'\n- ')
					maintext(u'%i "%s" (%s)' % (seltable_field[0], seltable_field[1], seltable_field[2]))
					seltable_fieldslist.append(str(seltable_field[1]))

				# count fields from selected table
				seltablecur.execute('SELECT COUNT(*) FROM %s' % seltable_tablename)
				seltable_rownumber = seltablecur.fetchall();
				maintext("\n\nThe selected table has %s rows" % seltable_rownumber[0][0])
				limit = rowsnumber
				offset = rowsoffset*rowsnumber
				maintext("\nShowing %i rows from row %i." % (limit, offset))
							
				# read all fields from selected table
				seltablecur.execute("SELECT * FROM %s LIMIT %i OFFSET %i" % (seltable_tablename, limit, offset))
				
				try:
				
					# appends records to main text field
					maintext("\n\nTable Records:")
					
					del photoImages[:]
					
					#for seltable_record in seltable_cont:
					for seltable_record in seltablecur:

						maintext("\n- " + str(seltable_record))
							
						for i, col in enumerate(seltable_record):	
						
							try:
								value = str(col)
							except:
								value = col.encode("utf8", "replace") + " (decoded unicode)"

							#maybe an image?
							if (seltable_fieldslist[i] == "data"):
								dataMagic = magic.whatis(value)
								maintext("\n- Binary data: (%s)" %dataMagic)
								if (dataMagic.partition("/")[0] == "image"):			
								
									im = Image.open(StringIO.StringIO(value))
									tkim = ImageTk.PhotoImage(im)
									photoImages.append(tkim)
									maintext("\n ")
									textarea.image_create(END, image=tkim)
									
								else:
									maintext("\n\n")	
									maintext(dump(value, 16, 1000))
											
							else:
								try:
									maintext("\n- " + seltable_fieldslist[i] + " : " + value)
								except:
									dataMagic = magic.whatis(value)
									maintext("\n- " + seltable_fieldslist[i] + "  (" + dataMagic + ")")
						
						maintext("\n---------------------------------------")
				
				except:
					print("Unexpected error:", sys.exc_info())
					
				seltabledb.close()		
			except:
				print("Unexpected error:", sys.exc_info())
				seltabledb.close()

	# Called when an element is clicked in the main tree frame ---------------------------------------------------
	
	old_label_image = None
	
	def OnClick(event=None):
	
		global fileNameForViewer
		global old_label_image
	
		if not tree.selection():
			return;
		
		# remove everything from tables tree
		for item in tablestree.get_children():
			tablestree.delete(item)
		
		# clear notebook additional panes
		notebook.hide(previewcolumn)
		notebook.hide(exifcolumn)
		
		item = tree.selection()[0]
		item_text = tree.item(item, "text")
		item_type = tree.set(item, "type")
		item_id = tree.set(item, "id")
		
		#skip "folders"
		if not item_type:
			return
		
		#clears textarea
		clearmaintext()
		
		# managing "standard" files
		if (item_type == "X"):	
			item_realpath = os.path.join(backup_path, item_text)
			fileNameForViewer = item_realpath
			maintext(u'Selected: ' + item_realpath)
			log(u'Opening file %s' % item_realpath)
			
			if (os.path.exists(item_realpath)):		
				
				filemagic = magic.file(item_realpath)
				
				#print file content (if text file) otherwise only first 50 chars
				if (filemagic == "ASCII text" or filemagic.partition("/")[0] == "text"):
					with open(item_realpath, 'rb') as fh:
						maintext("\n\nASCII content:\n\n")
						line = fh.readline()
						while line:
							line = fh.readline()
							maintext(line)
				else:
					with open(item_realpath, 'rb') as fh:
						text = fh.read(30)
						maintext("\n\nFirst 30 chars from file (string): ")
						maintext("\n" + hex2string(text))
			
				#if binary plist:
				if (filemagic.partition("/")[2] == "binary_plist"):					
					maintext("\n\nDecoding binary Plist file:\n\n")
					maintext(plistutils.readPlist(item_realpath))
			
			else:
				log(u'...troubles while opening file %s (does not exist)' % item_realpath)
			
			return

		maintext(u'Selected: %s (id %s)' % (item_text, item_id))
		
		data = mbdb.fileInformation(item_id)
		if not data:
			return
		
		item_permissions = data['permissions']
		item_userid      = data['userid']
		item_groupid     = data['groupid']
		item_mtime       = unicode(datetime.fromtimestamp(int(data['mtime'])))
		item_atime       = unicode(datetime.fromtimestamp(int(data['atime'])))
		item_ctime       = unicode(datetime.fromtimestamp(int(data['ctime'])))
		item_fileid      = data['fileid']
		item_link_target = data['link_target']
		item_datahash    = data['datahash']
		item_flag        = data['flag']
		
		maintext(u'\n\nElement type: ' + item_type)
		maintext(u'\nPermissions: ' + item_permissions)
		maintext(u'\nData hash: ')
		maintext(u'\n ' + item_datahash)
		maintext(u'\nUser id: ' + item_userid)
		maintext(u'\nGroup id: ' + item_groupid)
		maintext(u'\nLast modify time: ' + item_mtime)
		maintext(u'\nLast access Time: ' + item_atime)
		maintext(u'\nCreation time: ' + item_ctime)
		maintext(u'\nFile Key (obfuscated file name): ' + item_fileid)
		maintext(u'\nFlag: ' + item_flag)

		maintext(u'\n\nElement properties (from mdbd file):')
		for name, value in data['properties'].items():
			maintext(u'\n%s: %s' % (name, value))
		
		# treat sym links
		if (item_type == u'l'):
			maintext(u'\n\nThis item is a symbolic link to another file.')
			maintext(u'\nLink Target: ' + item_link_target)
			fileNameForViewer = u''
			return
			
		# treat directories
		if (item_type == u'd'):
			maintext(u'\n\nThis item represents a directory.')
			fileNameForViewer = u''
			return
		
		# last modification date of the file in the backup directory
		last_mod_time = time.strftime(u'%m/%d/%Y %I:%M:%S %p',time.localtime(os.path.getmtime(os.path.join(backup_path, item_fileid))))
		maintext(u'\n\nLast modification time (in backup dir): %s' % last_mod_time)
		
		maintext(u'\n\nAnalize file: ')
		
		item_realpath = os.path.join(backup_path, item_fileid)
		fileNameForViewer = item_realpath
		
		log(u'Opening file %s (%s)' % (item_realpath, item_text))
		
		# check for existence 
		if (not os.path.exists(item_realpath)):
			maintext(u'unable to analyze file')
			return			
		
		# print file type (from magic numbers)
		filemagic = magic.file(item_realpath)
		maintext(u'\nFile type (from magic numbers): %s' % filemagic)
		
		# print file MD5 hash
		maintext(u'\nFile MD5 hash: ')
		maintext(md5(item_realpath))
		
		#print first 30 bytes from file
		with open(item_realpath, u'rb') as fh:
			first30bytes = fh.read(30)
			maintext(u'\n\nFirst 30 hex bytes from file: ')
			maintext(u'\n' + hex2nums(first30bytes))
			
		#print file content (if ASCII file) otherwise only first 30 bytes
		if (filemagic == u'ASCII text' or filemagic.partition('/')[0] == u'text'):
			with open(item_realpath, 'rb') as fh:
				maintext(u'\n\nASCII content:\n\n')
				line = fh.readline()
				while line:
					line = fh.readline()
					maintext(line)
		else:
			maintext("\n\nFirst 30 chars from file (string): ")
			maintext("\n" + hex2string(first30bytes))					
		
		#if image file:
		if (filemagic.partition("/")[0] == "image"):		
			try:
				del photoImages[:]
				
				im = Image.open(item_realpath)
					
				#tkim = ImageTk.PhotoImage(im)
				#photoImages.append(tkim)
				maintext("\n\nImage preview available.")
				#textarea.image_create(END, image=tkim)
				
				# put image in the "preview" tab
				
				colwidth = 600
				imwidth = im.size[0]
				dimratio1 = (colwidth + 0.0) / (imwidth + 0.0)
				
				colheight = 500
				imheight = im.size[1]
				dimratio2 = (colheight + 0.0) / (imheight + 0.0)
				
				if (dimratio1 >= dimratio2):
					dimratio = dimratio2
				else:
					dimratio = dimratio1
				
				if (dimratio >= 1):
					dimratio = 1
				
				newwidth = int(im.size[0] * dimratio)
				newheight = int(im.size[1] * dimratio)

				im2 = im.resize((newwidth,newheight), Image.ANTIALIAS)
				tkim2 = ImageTk.PhotoImage(im2)
				photoImages.append(tkim2)
				
				label_image = Label(previewcolumn, image=tkim2)
				label_image.place(x=0,y=0)#,width=newwidth,height=newheight)
				if old_label_image is not None:
					old_label_image.destroy()
				old_label_image = label_image
				
				notebook.add(previewcolumn)
				
			except:
				print("Warning: error while trying to analyze image file \"%s\""%item_realpath)
				print sys.exc_info()
			
		#decode EXIF (only JPG)
		if (filemagic == "image/jpeg"):
			exifs = im._getexif()
			
			if (exifs is not None):
				maintext("\nJPG EXIF tags available.")
				exifcolumn_label.delete(1.0, END)
				exifcolumn_label.insert(END, "JPG EXIF tags for file \"%s\":"%item_text)
				exifcolumn_label.insert(END, "\n")
				for tag, value in exifs.items():
					decoded = TAGS.get(tag, tag)
					if (type(value) == type((1,2))):
						value = "%.3f (%i / %i)"%(float(value[0]) / float(value[1]), value[0], value[1])
					exifcolumn_label.insert(END, "\nTag: %s, value: %s"%(decoded, value))
				notebook.add(exifcolumn)
			
			#maintext("\n\nJPG EXIF tags:")
			#for tag, value in exifs.items():
			#	decoded = TAGS.get(tag, tag)
			#	maintext("\nTag: %s, value: %s"%(decoded, value))
				
		#if binary plist:
		if (filemagic.partition("/")[2] == "binary_plist"):			
			maintext("\n\nDecoding binary Plist file:\n\n")
			maintext(plistutils.readPlist(item_realpath))
		
		#if sqlite, print tables list
		if (filemagic.partition("/")[2] == "sqlite"):	
			tempdb = sqlite3.connect(item_realpath) 
			
			try:
				tempcur = tempdb.cursor() 
				tempcur.execute("SELECT name FROM sqlite_master WHERE type=\"table\"")
				tables_list = tempcur.fetchall();
				
				maintext("\n\nTables in database: ")
				
				for i in tables_list:
					table_name = str(i[0])
					maintext("\n- " + table_name);
					
					try:
						tempcur.execute("SELECT count(*) FROM %s" % table_name);
						elem_count = tempcur.fetchone()
						maintext(" (%i elements) " % int(elem_count[0]))
						# inserts table into tables tree
						tablestree.tag_configure('base', font=globalfont)
						tablestree.insert('', 'end', text=table_name, values=(item_realpath, table_name), tag="base")	
					except:
						#probably a virtual table?
						maintext(" (unable to read) ")
						
				tempdb.close()		
				
			except:
				maintext("\n\nSorry, I'm unable to open this database file. It appears to be an issue of some databases in iOS5.")
				maintext("\nUnexpected error: %s"%sys.exc_info()[1])
				tempdb.close()
			
		# if unknown "data", dump hex
		if (filemagic == "data"):
			limit = 10000
			maintext("\n\nDumping hex data (limit %i bytes):\n"%limit)
			content = ""
			with open(item_realpath, 'rb') as fh:
				line = fh.readline()
				while line:
					line = fh.readline()
					content += line;
			
			maintext(dump(content, 16, limit))

	# Main ---------------------------------------------------------------------------------------------------

	tree.bind("<ButtonRelease-1>", OnClick)
	tree.bind("<KeyRelease-Up>", OnClick)
	tree.bind("<KeyRelease-Down>", OnClick)

	tablestree.bind("<ButtonRelease-1>", TablesTreeClick)
	timebox.bind("<Key>", clearTimeBox)
	
	log("Welcome to the iPhone Backup browser by mario.piccinelli@gmail.com")
	log("Version: %s (%s)"%(version, creation_date))
	log("Working directory: %s"%backup_path)

	maintext("Welcome to the iPhone Backup browser by mario.piccinelli@gmail.com")
	maintext("\nVersion: %s (%s)"%(version, creation_date))
	maintext("\nWorking directory: %s"%backup_path)
	
	# Populating Device Info Box
	
	deviceinfo = plistutils.deviceInfo(os.path.join(backup_path, "Info.plist"))
	for element in deviceinfo:
		infobox.insert(INSERT, "%s: %s\n"%(element, deviceinfo[element]))


	root.focus_set()
	
	root.protocol("WM_DELETE_WINDOW", lambda:sys.exit(0))
	
	root.mainloop()
	
	database.close() # Close the connection to the database
	

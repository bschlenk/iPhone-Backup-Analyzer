#!/usr/bin/env python

'''
 Analyzer for iPhone backup made by Apple iTunes

 (C)opyright 2011 Mario Piccinelli <mario.piccinelli@gmail.com>
 Released under MIT licence

 cellocation.py provides the code to show a TK window to browse through
 the SQLite file which holds cell location data in the iPhone Backup.

'''

# IMPORTS -----------------------------------------------------------------------------------------

PLUGIN_NAME = "Cell Location"
import plugins_utils

from Tkinter import *
import tkMessageBox
import sqlite3
import ttk
from datetime import datetime
import os
import webbrowser

# GLOBALS -----------------------------------------------------------------------------------------

datetree = None
textarea = None
cellstree = None
filename = ""

def autoscroll(sbar, first, last):
    """Hide and show scrollbar as needed."""
    #first, last = float(first), float(last)
    #if first <= 0 and last >= 1:
    #    sbar.grid_remove()
    #else:
    #    sbar.grid()
    sbar.set(first, last)

# called when the user double clicks on the cell tree list ----------------------------------------

def OnCellDoubleClick(event):
	global filename
	global datetree, textarea, cellstree
	if (len(cellstree.selection()) == 0): return;
	lon = cellstree.set(cellstree.selection(), "lon")
	lat = cellstree.set(cellstree.selection(), "lat")
	url = "http://www.openstreetmap.org/index.html?mlat=%s&mlon=%s&zoom=12"%(lat, lon)
	webbrowser.open_new(url)
	
# called when the user clicks on the cell tree list ----------------------------------------------

def OnCellClick(event):
	global filename
	global datetree, textarea, cellstree
	if (len(cellstree.selection()) == 0): return
	mcc = cellstree.item(cellstree.selection(), "text")
	mnc = cellstree.set(cellstree.selection(), "mnc")
	lac = cellstree.set(cellstree.selection(), "lac")
	ci = cellstree.set(cellstree.selection(), "ci")
		
	lon = cellstree.set(cellstree.selection(), "lon")
	lat = cellstree.set(cellstree.selection(), "lat")
	alt = cellstree.set(cellstree.selection(), "alt")
	
	hacc = cellstree.set(cellstree.selection(), "hacc")
	vacc = cellstree.set(cellstree.selection(), "vacc")
	speed = cellstree.set(cellstree.selection(), "speed")
	course = cellstree.set(cellstree.selection(), "course")
	confidence = cellstree.set(cellstree.selection(), "confidence")
	
	# clears textarea
	textarea.delete(1.0, END)
	
	if (mcc == "" and mnc == ""): return
	
	textarea.insert(END, "MCC (mobile country code): %s\n"%mcc)	
	textarea.insert(END, "MNC (mobile network code): %s\n"%mnc)
	textarea.insert(END, "LAC (location area code): %s\n"%lac)
	textarea.insert(END, "CI (cell id): %s\n"%ci)
	textarea.insert(END, "\n")
	textarea.insert(END, "Latitude: %s\n"%lat)
	textarea.insert(END, "Longitude: %s\n"%lon)
	textarea.insert(END, "Altitude: %s\n"%alt)
	textarea.insert(END, "\n")
	textarea.insert(END, "Horizontal accuracy: %s\n"%hacc)
	textarea.insert(END, "Vertical accuracy: %s\n"%vacc)
	textarea.insert(END, "Speed: %s\n"%speed)
	textarea.insert(END, "Course: %s\n"%course)
	textarea.insert(END, "Confidence: %s\n"%confidence)
	

# Called when the user clicks on the main tree list -----------------------------------------------

def OnClick(event):
	global filename
	global datetree, textarea, cellstree
	if (len(datetree.selection()) == 0): return;
	timestamp = datetree.set(datetree.selection(), "timestamp")
	
	tempdb = sqlite3.connect(filename)
	tempcur = tempdb.cursor() 
	query = "SELECT MCC, MNC, LAC, CI, Latitude, Longitude, Altitude, HorizontalAccuracy, VerticalAccuracy, Speed, Course, Confidence FROM CellLocation WHERE timestamp = %s"%timestamp
	tempcur.execute(query)
	cells = tempcur.fetchall()
	
	if (len(cells) == 0):
		return
	
	# clears textarea
	textarea.delete(1.0, END)
	
	# clears cells tree
	allnodes = cellstree.get_children()
	for node in allnodes:
		cellstree.delete(node)
	
	# keeps totals for average values
	sum_lat = 0
	sum_lon = 0
	sum_alt = 0
	sum_num = 0
	
	# populates cells tree
	for cell in cells:
		mcc = cell[0]
		mnc = cell[1]
		lac = cell[2]
		ci = cell[3]
		latitude = cell[4]
		longitude = cell[5]
		altitude = cell[6]
		hacc = cell[7]
		vacc = cell[8]
		speed = cell[9]
		course = cell[10]
		confidence = cell[11]

		cellstree.insert('', 'end', text=mcc, values=(mnc, lac, ci, latitude, longitude, altitude, hacc, vacc, speed, course, confidence))
		
		# keep totals for calculating average
		sum_lat += latitude
		sum_lon += longitude
		sum_alt += altitude
		sum_num += 1
	
	# calculates and inserts average values
	cellstree.insert('', 'end', text="", values=("", "", "Average:", sum_lat/sum_num, sum_lon/sum_num, sum_alt/sum_num))

	tempdb.close()

# MAIN FUNCTION --------------------------------------------------------------------------------
	
def main(mbdb, backup_path):
	global filename
	global datetree, textarea, cellstree
	
	filename = os.path.join(backup_path, mbdb.realFileName(filename="consolidated.db", domaintype="RootDomain"))
	
	if (not os.path.isfile(filename)):
		print("Invalid file name for Cell Location database")
		return	
	
	# main window
	cellwindow = Toplevel()
	cellwindow.title('Cell Location data')
	cellwindow.focus_set()
	
	cellwindow.grid_columnconfigure(2, weight=1)
	cellwindow.grid_rowconfigure(1, weight=1)
	
	# header label
	celltitle = Label(cellwindow, text = "Cell Location data from: " + filename, relief = RIDGE)
	celltitle.grid(column = 0, row = 0, sticky="ew", columnspan=4, padx=5, pady=5)

	# tree of distinct timestamps
	datetree = ttk.Treeview(cellwindow, columns=("timestamp"),
	    displaycolumns=(), yscrollcommand=lambda f, l: autoscroll(mvsb, f, l))
	datetree.heading("#0", text="Timestamp", anchor='w')
	datetree.column("#0", width=200)	
	datetree.grid(column = 0, row = 1, sticky="ns")

	# scrollbars for tree
	mvsb = ttk.Scrollbar(cellwindow, orient="vertical")
	mvsb.grid(column=1, row=1, sticky='ns')
	mvsb['command'] = datetree.yview
	
	# main block
	mainblock = Frame(cellwindow, bd=2, relief=RAISED);
	mainblock.grid(column=2, row=1, sticky="nsew")
	mainblock.grid_columnconfigure(0, weight=1)
	mainblock.grid_rowconfigure(2, weight=1)

	# main block label
	mainblocklabel = Label(mainblock, text="Click on the list to show description, double click to show location in browser", relief=RIDGE)
	mainblocklabel.grid(column = 0, row = 0, sticky="nsew")

	# tree
	cellstree = ttk.Treeview(mainblock, 
		columns=("mnc", "lac", "ci", "lat", "lon", "alt", "hacc", "vacc", "speed", "course", "confidence"),
	    displaycolumns=("mnc", "lac", "ci", "lat", "lon", "alt"))
	
	cellstree.heading("#0", text="MCC", anchor='w')
	cellstree.column("#0", width=30)

	cellstree.heading("mnc", text="MNC", anchor='w')
	cellstree.column("mnc", width=30)

	cellstree.heading("lac", text="LAC", anchor='w')
	cellstree.column("lac", width=30)

	cellstree.heading("ci", text="CI", anchor='w')
	cellstree.column("ci", width=50)

	cellstree.heading("lat", text="LAT", anchor='w')
	cellstree.column("lat", width=60)

	cellstree.heading("lon", text="LON", anchor='w')
	cellstree.column("lon", width=60)
	
	cellstree.heading("alt", text="ALT", anchor='w')
	cellstree.column("alt", width=50)
	
	cellstree.grid(column = 0, row = 1, sticky="nsew")

	# textarea
	textarea = Text(mainblock, bd=2, relief=SUNKEN, yscrollcommand=lambda f, l: autoscroll(tvsb, f, l))
	textarea.grid(column = 0, row = 2, sticky="nsew")

	# scrollbars for main textarea
	tvsb = ttk.Scrollbar(mainblock, orient="vertical")
	tvsb.grid(column=1, row=2, sticky='ns')
	tvsb['command'] = textarea.yview
		
	# footer label
	footerlabel = StringVar()
	cellfooter = Label(cellwindow, textvariable = footerlabel, relief = RIDGE)
	cellfooter.grid(column = 0, row = 2, sticky="ew", columnspan=4, padx=5, pady=5)
	
	# destroy window when closed
	cellwindow.protocol("WM_DELETE_WINDOW", cellwindow.destroy)
	
	# opening database
	tempdb = sqlite3.connect(filename)
	tempcur = tempdb.cursor() 
	
	# footer statistics
	query = "SELECT count(*) FROM CellLocation"
	try:
		tempcur.execute(query)
	except sqlite3.OperationalError:
		tkMessageBox.showwarning('Cell Location', 'this is only available for backups of iOS version 4.3 or lower')
		cellwindow.destroy()
		return

	cellsnumber = tempcur.fetchall()[0][0]
	query = "SELECT DISTINCT(timestamp) FROM CellLocation ORDER BY timestamp"
	tempcur.execute(query)
	disttimestamps = tempcur.fetchall()
	footerlabel.set("Found %s cell locations in %s distinct timestamps."%(cellsnumber, len(disttimestamps)))

	# populating tree with distinct timestamps
	for timestamp in disttimestamps:
		raw = timestamp[0]
		converted = raw + 978307200 #JAN 1 1970
		converted = datetime.fromtimestamp(int(converted))
		datetree.insert('', 'end', text=converted, values=(raw))
		
	datetree.bind("<ButtonRelease-1>", OnClick)
	cellstree.bind("<Double-Button-1>", OnCellDoubleClick)
	cellstree.bind("<ButtonRelease-1>", OnCellClick)

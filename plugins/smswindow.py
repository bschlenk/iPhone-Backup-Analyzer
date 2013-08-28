#!/usr/bin/env python

'''
 Analyzer for iPhone backup made by Apple iTunes

 (C)opyright 2011 Mario Piccinelli <mario.piccinelli@gmail.com>
 Released under MIT licence

 smswindow.py provides the code to show a TK window to browse through
 the SQLite file which holds the SMS data in the iPhone Backup.

'''

# IMPORTS -----------------------------------------------------------------------------------------

PLUGIN_NAME = "SMS Browser"
import plugins_utils

from Tkinter import *
import ttk
from datetime import datetime
import os
import sqlite3

# GLOBALS -----------------------------------------------------------------------------------------

groupstree = None
textarea = None
filename = ""

def autoscroll(sbar, first, last):
    """Hide and show scrollbar as needed."""
    #first, last = float(first), float(last)
    #if first <= 0 and last >= 1:
    #    sbar.grid_remove()
    #else:
    #    sbar.grid()
    sbar.set(first, last)

# Called when the user clicks on the main tree list -----------------------------------------------

def OnClick(event):
	global filename
	global groupstree, textarea
	if not len(groupstree.selection()):
		return;
	msg_group = int(groupstree.item(groupstree.selection(), "text"))
	msg_address = groupstree.set(groupstree.selection(), "address")
	
	messages = []
	
	tempdb = sqlite3.connect(filename)
	tempcur = tempdb.cursor()
	 
	query = '''
		SELECT text, date, flags, message.ROWID
		FROM message
		INNER JOIN msg_group
		ON msg_group.rowid = message.group_id
		WHERE msg_group.rowid = ?
		ORDER BY date
	'''
	tempcur.execute(query, (msg_group,))
	for newElem in tempcur:
		try:
			text = str(newElem[0])
		except:
			text = newElem[0].encode("utf8", "replace")
		
		flag = int(newElem[2])
		if (flag == 2):
			status = "Received"
		elif (flag == 3):
			status = "Sent"
		else:
			status = "(status %i unknown)" % flag
		
		newMess = [
			text,
			int(newElem[1]),
			status,
			int(newElem[3])	
		]
		
		messages.append(newMess)
	
	query = '''
		SELECT text, date, madrid_flags, ROWID
		FROM message
		WHERE is_madrid = 1 AND madrid_handle = ?
		ORDER BY ROWID
	'''
	tempcur.execute(query2, (msg_address))
	for newElem in tempcur:
		try:
			text = str(newElem[0])
		except:
			text = newElem[0].encode("utf8", "replace")
		
		flag = int(newElem[2])
		if (flag == 12289):
			status = "Received (by Madrid)"
		elif (flag == 36869):
			status = "Sent (by Madrid)"
		else:
			status = "(status %i unknown)"%flag
		
		newMess = [
			text,
			int(newElem[1]) + 978307200,
			status,
			int(newElem[3])	
		]
		
		messages.append(newMess)
		
	textarea.delete(1.0, END)
	
	curday = 0
	curmonth = 0
	curyear = 0
	
	for message in messages:
		
		text = message[0]
		date = message[1]
		status    = message[2]
		messageid = message[3]
		
		convdate = datetime.fromtimestamp(date)
		newday   = convdate.day
		newmonth = convdate.month
		newyear  = convdate.year
		
		# checks whether the day is the same from the last message
		changeday = 0
		if (curday != newday) or (curmonth != newmonth) or (curyear != newyear): 
			changeday = 1
			curday = newday
			curmonth = newmonth
			curyear = newyear
			
		# if day changed print a separator with date	
		if (changeday == 1):
			textarea.insert(END, "\n******** %s ********\n" % convdate.date())
		else:
			textarea.insert(END, "-------\n")
		
		# prints message date and text
		textarea.insert(END, "%s in date: %s\n" % (status,convdate))
		textarea.insert(END, "%s\n" % text)
		
		# other message parts (from table message_id)
		query = '''
			SELECT part_id, content_type, content_loc
			FROM msg_pieces
			WHERE message_id = ?
			ORDER BY part_id
		'''
		tempcur.execute(query, (messageid,))
		
		# prints attachments under the message text
		for attachment in tempcur:
			part_id = attachment[0]
			content_type = attachment[1]
			content_loc = attachment[2]
			textarea.insert(END, "-> %i - %s (%s)\n" % (part_id, content_type, content_loc))

	tempdb.close()

# MAIN FUNCTION --------------------------------------------------------------------------------

def main(mbdb, backup_path):
	global filename
	global groupstree, textarea
	
	filename = os.path.join(backup_path, mbdb.realFileName(filename="sms.db", domaintype="HomeDomain"))
	
	if not os.path.isfile(filename):
		print("Invalid file name for SMS database")
		return	
	
	# main window
	smswindow = Toplevel()
	smswindow.title('SMS data')
	smswindow.focus_set()
	
	smswindow.grid_columnconfigure(2, weight=1)
	smswindow.grid_rowconfigure(1, weight=1)
	
	# header label
	smstitle = Label(smswindow, text="SMS data from: %s" % filename, relief=RIDGE)
	smstitle.grid(column=0, row=0, sticky='ew', columnspan=4, padx=5, pady=5)

	# tree
	groupstree = ttk.Treeview(smswindow, columns=("address"),
	    displaycolumns=("address"), yscrollcommand=lambda f, l: autoscroll(mvsb, f, l))
	
	groupstree.heading("#0", text="ID", anchor='w')
	groupstree.heading("address", text="Address", anchor='w')
	
	groupstree.column("#0", width=30)
	groupstree.column("address", width=200)
	
	groupstree.grid(column = 0, row = 1, sticky="ns", rowspan=2)

	# upper textarea
	uppertextarea = Text(smswindow, bd=2, relief=SUNKEN, height=5)
	uppertextarea.grid(column = 2, row = 1, sticky="nsew")
	
	# textarea
	textarea = Text(smswindow, bd=2, relief=SUNKEN, yscrollcommand=lambda f, l: autoscroll(tvsb, f, l))
	textarea.grid(column = 2, row = 2, sticky="nsew")

	# scrollbars for tree
	mvsb = ttk.Scrollbar(smswindow, orient="vertical")
	mvsb.grid(column=1, row=1, sticky='ns', rowspan=2)
	mvsb['command'] = groupstree.yview

	# scrollbars for main textarea
	tvsb = ttk.Scrollbar(smswindow, orient="vertical")
	tvsb.grid(column=3, row=2, sticky='ns')
	tvsb['command'] = textarea.yview
		
	# footer label
	footerlabel = StringVar()
	smsfooter = Label(smswindow, textvariable=footerlabel, relief=RIDGE)
	smsfooter.grid(column=0, row=3, sticky="ew", columnspan=4, padx=5, pady=5)
	
	# destroy window when closed
	smswindow.protocol("WM_DELETE_WINDOW", smswindow.destroy)
	
	# opening database
	tempdb = sqlite3.connect(filename)
	tempcur = tempdb.cursor() 
	
	# footer statistics
	tempcur.execute('SELECT count(ROWID) FROM msg_group')
	groupsnumber = tempcur.fetchone()[0]
	tempcur.execute('SELECT count(ROWID) FROM message')
	smsnumber = tempcur.fetchone()[0]
	footerlabel.set("Found %s messages in %s groups." % (smsnumber, groupsnumber))
	
	# uppertextarea statistics
	def readKey(key):
		query = '''
			SELECT value
			FROM _SqliteDatabaseProperties
			WHERE key = ?
		'''
		tempcur.execute(query, (key,))
		data = tempcur.fetchall()
		if data:
			value = data[0][0]
		else:
			value = 0
		return value
	
	uppertextarea.insert(END, "Incoming messages (after last reset): %s\n" % (readKey("counter_in_all")))	
	uppertextarea.insert(END, "Lifetime incoming messages: %s\n" % readKey("counter_in_lifetime"))
	uppertextarea.insert(END, "Outgoing messages (after last reset): %s\n" % readKey("counter_out_all"))
	uppertextarea.insert(END, "Lifetime outgoing messages: %s\n" % readKey("counter_out_lifetime"))
	uppertextarea.insert(END, "Counter last reset: %s\n" % readKey("counter_last_reset"))
	
	# populating tree with SMS groups
	query = '''
		SELECT DISTINCT(msg_group.rowid), address
		FROM msg_group
		INNER JOIN group_member
		ON msg_group.rowid = group_member.group_id
	'''
	tempcur.execute(query)
	groups = tempcur.fetchall()
	tempdb.close()
	
	for group in groups:
		groupid = group[0]
		address = group[1].replace(' ', '')
		groupstree.insert('', 'end', text=groupid, values=(address))
		
	groupstree.bind("<ButtonRelease-1>", OnClick)

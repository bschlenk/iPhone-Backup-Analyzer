#!/usr/bin/python
# -*- coding: utf-8 -*-
import struct
import sqlite3
import hashlib
	
class ManifestDatabaseError(Exception):
	pass

class ManifestDatabase(sqlite3.Connection):

	@staticmethod
	def connect():
		return sqlite3.connect(':memory:', factory=ManifestDatabase)

	def __init__(self, *args, **kwargs):
		super(ManifestDatabase, self).__init__(*args, **kwargs)

		cursor = self.cursor()
		cursor.execute(u'''
			CREATE TABLE indice (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				type TEXT,
				permissions TEXT,
				userid TEXT,
				groupid TEXT,
				filelen INT,
				mtime INT,
				atime INT,
				ctime INT,
				fileid TEXT,
				domain_type TEXT,
				domain TEXT,
				file_path TEXT,
				file_name TEXT,
				link_target TEXT,
				datahash TEXT,
				flag TEXT
			)
		''')
		
		cursor.execute(u'''
			CREATE TABLE properties (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				fileid INTEGER,
				name TEXT,
				value TEXT
			)
		''')
		
	
	_insertStatement = u'''
		INSERT INTO indice(
			type, 
			permissions, 
			userid, 
			groupid, 
			filelen, 
			mtime, 
			atime, 
			ctime, 
			fileid, 
			domain_type, 
			domain, 
			file_path, 
			file_name, 
			link_target, 
			datahash, 
			flag
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

	def insertRecord(self, rec):
		# decoding element type (symlink, file, directory)
		if (rec[u'mode']   & 0xE000) == 0xA000: obj_type = u'l' # symlink
		elif (rec[u'mode'] & 0xE000) == 0x8000: obj_type = u'-' # file
		elif (rec[u'mode'] & 0xE000) == 0x4000: obj_type = u'd' # dir
			
		# separates domain type (AppDomain, HomeDomain, ...) from domain name
		[domaintype, sep, domain] = rec[u'domain'].partition(u'-');
			
		# separates file name from file path
		if (obj_type == u'd'):
			filepath = rec[u'path']
			filename = u'';
		else:
			[filepath, sep, filename] = rec[u'path'].rpartition(u'/')

		values = (obj_type, self._modestr(rec[u'mode']), hex(rec[u'userid']), hex(rec[u'groupid']), rec[u'filelength'], 
			rec[u'mtime'], rec[u'atime'], rec[u'ctime'], rec[u'fileid'], domaintype, domain, filepath, filename,
			rec[u'linktarget'], rec[u'datahash'], rec[u'flag'],
		)
		
		cursor = self.cursor()
		cursor.execute(ManifestDatabase._insertStatement, values)
		
		# check if file has properties to store in the properties table
		if (rec[u'properties']):

			query = u'''
				SELECT id FROM indice WHERE
				domain = ?
				AND fileid = ?
				LIMIT 1
			'''
			 
			cursor.execute(query, (domain, rec[u'fileid']))
			rowid = cursor.fetchone()
			
			if (rowid):
				index = rowid[0]
				properties = rec[u'properties']
				query = u'INSERT INTO properties(fileid, name, value) VALUES (?, ?, ?)'
				values = [(index, p, properties[p]) for p in properties]
				cursor.executemany(query, values);

		cursor.close()
		self.commit()

	def _modestr(self, val):
		def mode(val):
			if (val & 0x4): r = u'r'
			else: r = '-'
			if (val & 0x2): w = u'w'
			else: w = '-'
			if (val & 0x1): x = u'x'
			else: x = u'-'
			return r+w+x
		val = val & 0x0FFF
		return mode(val>>6) + mode((val>>3)) + mode(val)
		

class ManifestMBDBError(Exception):
	pass

class ManifestMBDB(object):
	def __init__(self, fname):
		self.fname = fname

		with open(fname, 'rb') as f:
			data = f.read()

		header = data[:4]
		if header != 'mbdb':
			raise ManifestMBDBError(u'"%s" is not a valid mbdb file' % fname)
		self.version = u'mbdb %s' % repr((ord(data[4]), ord(data[5])))

		self._db = ManifestDatabase.connect()

		offset = 6
		dataLength = len(data)
		self.records = []
		while offset < dataLength:
			record, offset = self._decodeRecord(data, offset)
			self.records.append(record)
			self._db.insertRecord(record)

	
	def __list__(self):
		return self.records

	def __len__(self):
		return len(self.records)

	def __iter__(self):
		return iter(self.records)

	def __getitem__(self, key):
		return self.records[key]

	def _decodeRecord(self, data, offset):
		record = {}
		record[u'domain'], offset     = self._decodeString(data, offset)
		record[u'path'], offset       = self._decodeString(data, offset)
		record[u'linktarget'], offset = self._decodeString(data, offset)
		record[u'datahash'], offset   = self._decodeSha1(data, offset)
		record[u'unknown1'], offset   = self._decodeString(data, offset)
		record[u'mode'], offset       = self._decodeUint16(data, offset)
		record[u'unknown2'], offset   = self._decodeUint32(data, offset)
		record[u'unknown3'], offset   = self._decodeUint32(data, offset)
		record[u'userid'], offset     = self._decodeUint32(data, offset)
		record[u'groupid'], offset    = self._decodeUint32(data, offset)
		record[u'mtime'], offset      = self._decodeUint32(data, offset)
		record[u'atime'], offset      = self._decodeUint32(data, offset)
		record[u'ctime'], offset      = self._decodeUint32(data, offset)
		record[u'filelength'], offset = self._decodeUint64(data, offset)
		record[u'flag'], offset       = self._decodeUint8(data, offset)
		numProperties, offset = self._decodeUint8(data, offset)
		record[u'properties'] = {}
		for x in range(numProperties):
			prop, offset = self._decodeString(data, offset)
			value, offset = self._decodeString(data, offset)
			record[u'properties'][prop] = value
		sha1 = hashlib.sha1()
		sha1.update((u'%s-%s' % (record[u'domain'], record[u'path'])).encode('utf-8'))
		record[u'fileid'] = sha1.hexdigest()	
		return (record, offset)

	def _decodeUint8(self, data, offset):
		num = struct.unpack('>B', data[offset:offset+1])[0]
		return (num, offset + 1)

	def _decodeUint16(self, data, offset):
		num = struct.unpack('>H', data[offset:offset+2])[0]
		return (num, offset + 2)

	def _decodeUint32(self, data, offset):
		num = struct.unpack('>I', data[offset:offset+4])[0]
		return (num, offset + 4)

	def _decodeUint64(self, data, offset):
		num = struct.unpack('>Q', data[offset:offset+8])[0]
		return (num, offset + 8)

	def _decodeString(self, data, offset):
		if data[offset:offset+2].encode('hex') == 'ffff': #empty string
			return (u'', offset + 2)
		length, offset = self._decodeUint16(data, offset)
		string = data[offset:offset+length]
		try:
			string = string.decode('utf-8')
		except UnicodeDecodeError:
			pass
		return (string, offset + length)

	def _decodeSha1(self, data, offset):
		if data[offset:offset+2].encode('hex') == 'ffff': #empty string
			return (u'', offset + 2)
		length, offset = self._decodeUint16(data, offset)
		string = data[offset:offset+length].encode('hex')
		return (string, offset + length)
		

if __name__ == '__main__':
	import os, sys
	backup_folder = os.path.join(os.path.expanduser(u'~'), u'Library/Application Support/MobileSync/Backup/')
	backups = sorted(os.listdir(backup_folder), key=lambda x: os.path.getmtime(os.path.join(backup_folder, x)))

	for i, f in enumerate(backups):
		print u'%d: %s' % (i, f)
	choice = raw_input(u'select backup: ')

	if choice:
		try:
			choice = int(choice)
		except ValueError:
			print u'choice must be a number'
			sys.exit(1)
		
		try:
			backup = backups[choice]
		except IndexError:
			print u'invalid choice'
			sys.exit(1)
	else:
		backup = backups[-1]

	mbdb = ManifestMBDB(os.path.join(backup_folder, backup, u'Manifest.mbdb'))
	print mbdb.version

	for rec in mbdb:
		print rec[u'domain'], rec[u'path'], oct(rec[u'mode']), rec[u'datahash']

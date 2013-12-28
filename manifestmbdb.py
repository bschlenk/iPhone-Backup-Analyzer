#!/usr/bin/python
# -*- coding: utf-8 -*-
import struct
import sqlite3
import hashlib
	
class ManifestDatabaseError(Exception):
	pass

class ManifestDatabase(sqlite3.Connection):

	@staticmethod
	def connect(db_file=':memory:'):
		conn = sqlite3.connect(db_file, factory=ManifestDatabase)
		conn.row_factory = sqlite3.Row
		return conn

	def __init__(self, *args, **kwargs):
		super(ManifestDatabase, self).__init__(*args, **kwargs)

		cursor = self.cursor()
		cursor.execute(u'''
			CREATE TABLE indice (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				type VARCHAR(1),
				permissions VARCHAR(9),
				userid VARCHAR(8),
				groupid VARCHAR(8),
				filelen INT,
				mtime INT,
				atime INT,
				ctime INT,
				fileid VARCHAR(50),
				domain_type VARCHAR(100),
				domain VARCHAR(100),
				file_path VARCHAR(100),
				file_name VARCHAR(100),
				link_target VARCHAR(100),
				datahash VARCHAR(100),
				flag VARCHAR(100)
			)
		''')
		
		cursor.execute(u'''
			CREATE TABLE properties (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				fileid INTEGER,
				name VARCHAR(100),
				value VARCHAR(100)
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

	def insertRecord(self, rec, commit=True):
		# decoding element type (symlink, file, directory)
		if (rec[u'mode']   & 0xE000) == 0xA000: obj_type = u'l' # symlink
		elif (rec[u'mode'] & 0xE000) == 0x8000: obj_type = u'-' # file
		elif (rec[u'mode'] & 0xE000) == 0x4000: obj_type = u'd' # dir

		# separates domain type (AppDomain, HomeDomain, ...) from domain name
		[domaintype, sep, domain] = rec[u'domain'].partition(u'-');

		# separates file name from file path
		[filepath, sep, filename] = rec['path'].rpartition(u'/')

		# TODO: why does this work??? Old code had typo here and made things work
		'''
		if (obj_type == u'd'):
			filepath = rec['path']
			filename = u'';
		'''

		values = (obj_type, self._modestr(rec['mode']), '%08x' % (rec['userid']), '%08x' % (rec['groupid']), rec['filelength'], 
			rec['mtime'], rec['atime'], rec['ctime'], rec['fileid'], domaintype, domain, filepath, filename,
			rec['linktarget'], rec['datahash'], rec['flag'],
		)

		cursor = self.cursor()
		cursor.execute(ManifestDatabase._insertStatement, values)
		
		# check if file has properties to store in the properties table
		if (rec['properties']):
			query = u'''
				SELECT id FROM indice WHERE
				domain = ?
				AND fileid = ?
				LIMIT 1
			'''
			 
			cursor.execute(query, (domain, rec['fileid']))
			rowid = cursor.fetchone()
			
			if (rowid):
				index = rowid[0]
				properties = rec['properties']
				query = u'INSERT INTO properties(fileid, name, value) VALUES (?, ?, ?)'
				values = [(index, p, properties[p]) for p in properties]
				cursor.executemany(query, values);

		cursor.close()
		if commit:
			self.commit()

	def _modestr(self, val):
		"""Return the string representation of a mode octal"""
		def mode(val):
			r = u'r' if (val & 0x4) else u'-'
			w = u'w' if (val & 0x2) else u'-'
			x = u'x' if (val & 0x1) else u'-'
			return r+w+x

		val = val & 0x0FFF
		return mode(val>>6) + mode((val>>3)) + mode(val)
		

class ManifestMBDBError(Exception):
	pass

class ManifestMBDB(object):
	def __init__(self, fname, db_file=None, create_database=True):
		self.fname = fname

		try:
			with open(fname, 'rb') as f:
				data = f.read()
		except IOError as e:
			raise ManifestMBDBError(str(e))

		header = data[:4]
		if header != 'mbdb':
			raise ManifestMBDBError(u'"%s" is not a valid mbdb file' % fname)
		self.version = u'mbdb %s' % repr((ord(data[4]), ord(data[5])))

		if create_database:
			if db_file:
				self._db = ManifestDatabase.connect(db_file)
			else:
				self._db = ManifestDatabase.connect()
		else:
			self._db = None

		offset = 6
		dataLength = len(data)
		self.records = []
		while offset < dataLength:
			record, offset = self._decodeRecord(data, offset)
			self.records.append(record)
			if create_database:
				self._db.insertRecord(record, commit=False)

		if create_database:
			self._db.commit()

	
	def __list__(self):
		return self.records

	def __len__(self):
		return len(self.records)

	def __iter__(self):
		return iter(self.records)

	def __getitem__(self, key):
		return self.records[key]

	def realFileName(self, filename='', domaintype='', path=''):
		"""Queries the database for the sha1 hash of the file given the arguments"""
		query = u'SELECT fileid FROM indice'

		values = (filename, domaintype, path)
		fields = [u'file_name', u'domain_type', u'file_path']
		where_clause = u' AND '.join(u'%s = ?' % (k, ) for k, v in zip(fields, values) if v)
		if where_clause:
			query = u' WHERE '.join([query, where_clause])

		values = [v for v in values if v]

		cursor = self._db.cursor()
		cursor.execute(query, values);
		result = cursor.fetchone()
		cursor.close()
				
		if (result):
			return result[0]
		else:
			print(u'ERROR: could not find file')
			return ''	
	
	def domainTypes(self):
		"""Return a list of distinct domain types"""
		cursor = self._db.cursor()
		cursor.execute(u'SELECT DISTINCT(domain_type) FROM indice ORDER BY domain_type ASC');
		domain_types = [x[0] for x in list(cursor)]
		cursor.close()
		return domain_types

	def domainTypeMembers(self, domainType):
		"""Return a list of distinct domain names of the given domain type"""
		query = u'''
			SELECT DISTINCT(domain)
			FROM indice
			WHERE domain_type = ?
			ORDER BY domain ASC
		'''
		cursor = self._db.cursor()
		cursor.execute(query, (domainType,))
		domain_members = [x[0] for x in list(cursor)]
		cursor.close()
		return domain_members


	def filePathsOfDomain(self, domainType, domainName):
		"""Return a list of all the files under the given domain"""
		query = u'''
			SELECT DISTINCT(file_path)
			FROM indice
			WHERE domain_type = ? AND domain = ?
			ORDER BY file_path ASC
		'''
		cursor = self._db.cursor()
		cursor.execute(query, (domainType, domainName))
		paths = [x[0] for x in list(cursor)]
		cursor.close()
		return paths


	def filesInDir(self, domainType, domainName, filePath):
		"""Return a list of file information for the files in the given category"""
		# used to be: SELECT file_name, filelen, id, type
		query = u'''
			SELECT *
			FROM indice 
			WHERE domain_type = ? AND domain = ? AND file_path = ?
			ORDER BY file_name ASC
		'''
		cursor = self._db.cursor()
		cursor.execute(query, (domainType, domainName, filePath))
		files = cursor.fetchall()
		cursor.close()
		return files


	def fileInformation(self, item_id):
		"""Return the file information for the file with the given id"""
		query = u'''
			SELECT * FROM indice 
			WHERE id = ?
		'''
		cursor = self._db.cursor()
		cursor.execute(query, (item_id,))
		data = dict(cursor.fetchone())
		query = u'''
			SELECT name, value
			FROM properties
			WHERE fileid = ?
		'''
		cursor.execute(query, (item_id,))
		properties = dict([(row['name'], row['value']) for row in cursor])
		cursor.close()
		data['properties'] = properties
		return data

	def fileId(self, filename, filePath):
		"""Return the file id of the file matching the criteria, None if not found"""
		query = u'''
			SELECT id
			FROM indice
		'''
		fields = [u'file_name', u'file_path']
		values = [filename, filePath]
		where_clause = u' AND '.join([u'%s = ?' % k for k, v in zip(fields, values) if v])
		if where_clause:
			query = u' WHERE '.join([query, where_clause])

		values = [f for f in values if f]
		cursor = self._db.cursor()
		cursor.execute(query, values)
		row = cursor.fetchone()
		cursor.close()
		if row:
			return row[0]
		return None


	def _decodeRecord(self, data, offset):
		"""Decode and return a single record from the .mbdb file"""
		record = {}
		record['domain'], offset     = self._decodeString(data, offset)
		record['path'], offset       = self._decodeString(data, offset)
		record['linktarget'], offset = self._decodeString(data, offset)
		record['datahash'], offset   = self._decodeSha1(data, offset)
		record['unknown1'], offset   = self._decodeString(data, offset)
		record['mode'], offset       = self._decodeUint16(data, offset)
		record['unknown2'], offset   = self._decodeUint32(data, offset)
		record['unknown3'], offset   = self._decodeUint32(data, offset)
		record['userid'], offset     = self._decodeUint32(data, offset)
		record['groupid'], offset    = self._decodeUint32(data, offset)
		record['mtime'], offset      = self._decodeUint32(data, offset)
		record['atime'], offset      = self._decodeUint32(data, offset)
		record['ctime'], offset      = self._decodeUint32(data, offset)
		record['filelength'], offset = self._decodeUint64(data, offset)
		record['flag'], offset       = self._decodeUint8(data, offset)
		numProperties, offset = self._decodeUint8(data, offset)
		record['properties'] = {}
		for x in range(numProperties):
			prop, offset = self._decodeString(data, offset)
			value, offset = self._decodeString(data, offset)
			record['properties'][prop] = value
		sha1 = hashlib.sha1()
		sha1.update((u'%s-%s' % (record['domain'], record['path'])).encode('utf-8'))
		record['fileid'] = sha1.hexdigest()	
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
			string = string.encode('hex').encode('utf-8')
		return (string, offset + length)

	def _decodeSha1(self, data, offset):
		if data[offset:offset+2].encode('hex') == 'ffff': #empty string
			return (u'', offset + 2)
		length, offset = self._decodeUint16(data, offset)
		string = data[offset:offset+length].encode('hex').encode('utf-8')
		return (string, offset + length)
		

if __name__ == '__main__':
	import os, sys
	backup_folder = os.path.join(os.path.expanduser(u'~'), u'Library/Application Support/MobileSync/Backup/')
	backups = sorted(os.listdir(backup_folder), key=lambda x: os.path.getmtime(os.path.join(backup_folder, x)))

	if len(sys.argv) == 2 and sys.argv[1] == '-f':
		backup = backups[-1]
	else:
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

	mbdb = ManifestMBDB(os.path.join(backup_folder, backup, u'Manifest.mbdb'), create_database=False)
	print mbdb.version

	for rec in sorted(mbdb, key = lambda x: x['domain'] + x['path']):
		print rec['domain'], rec['path'], rec['linktarget'], rec['userid'], rec['groupid'], oct(rec['mode']), rec['datahash'], len(rec['properties'])

import sqlite3

class IPBADatabase(sqlite3.Connection):
	def connect():
		return sqlite3.connect(u':memory:', factory=IPBADatabase)

	def __init__(self):
		super().__init__()
		self._createTables()

	def _createTables(self):
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
				file_id INTEGER,
				property_name VARCHAR(100),
				property_val VARCHAR(100)
			)
		''')

		cursor.close()
		self.commit()
	
	def insertRecord(self, ...):
		query = u'''
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
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'''
		query += "'%s'," 	% obj_type
		query += "'%s'," 	% mbdbdecoding.modestr(fileinfo['mode']&0x0FFF)
		query += "'%08x'," 	% fileinfo['userid']
		query += "'%08x'," 	% fileinfo['groupid']
		query += "%i," 		% fileinfo['filelen']
		query += "%i," 		% fileinfo['mtime']
		query += "%i," 		% fileinfo['atime']
		query += "%i," 		% fileinfo['ctime']
		query += "'%s'," 	% fileinfo['fileID']
		query += "'%s'," 	% domaintype.replace("'", "''")
		query += "'%s'," 	% domain.replace("'", "''")
		query += "'%s'," 	% filepath.replace("'", "''")
		query += "'%s'," 	% filename.replace("'", "''")
		query += "'%s'," 	% fileinfo['linktarget']
		query += "'%s'," 	% hex2nums(fileinfo['datahash']).replace("'", "''")
		query += "'%s'" 	% fileinfo['flag']
		query += ");"
		
		#print(query)

		cursor.execute(query)

	def realFileName(filename=u'', domaintype=u'', path=u''):
		query = u'SELECT fileid FROM indice'

		fields = [u'file_name', u'domain_type', u'file_path']
		where_clause = u' AND '.join(u'%s = ?' % k for k, v in zip(fields, (filename, domaintype, path)) if v)
		if where_clause:
			query = u' WHERE '.join([query, where_clause])

		params = tuple([x for x in (filename, domaintype, path) if x])

		cursor.execute(query, params);
		results = cursor.fetchone()
				
		if (results):
			return results[0]
		else:
			print('ERROR: could not find file')
			return u''	

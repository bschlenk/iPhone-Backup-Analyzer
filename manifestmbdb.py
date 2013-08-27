import struct

class ManifestMBDBError(Exception):
	pass

class ManifestMBDB(object):
	def __init__(self, fname):
		self.fname = fname

		with open(fname, 'rb') as f:
			data = f.read()

		header = data[:4]
		if header != 'mbdb':
			raise ManifestMBDBError('"%s" is not a valid mbdb file' % fname)
		self.version = 'mbdb %s' % repr((ord(data[4]), ord(data[5])))

		offset = 6
		dataLength = len(data)
		self.records = []
		while offset < dataLength:
			record, offset = self._decodeRecord(data, offset)
			self.records.append(record)
	
	def __list__(self):
		return self.records

	def __len__(self):
		return len(self.records)

	def __iter__(self):
		return iter(self.records)

	def _decodeRecord(self, data, offset):
		record = {}
		record['domain'], offset     = self._decodeString(data, offset)
		record['path'], offset       = self._decodeString(data, offset)
		record['linktarget'], offset = self._decodeString(data, offset)
		record['datahash'], offset   = self._decodeString(data, offset)
		record['unknown1'], offset   = self._decodeString(data, offset)
		record['mode'], offset       = self._decodeUint16(data, offset)
		record['unknown2'], offset   = self._decodeUint32(data, offset)
		record['unknown3'], offset   = self._decodeUint32(data, offset)
		record['userid'], offset     = self._decodeUint32(data, offset)
		record['groupid'], offset    = self._decodeUint32(data, offset)
		record['time1'], offset      = self._decodeUint32(data, offset)
		record['time2'], offset      = self._decodeUint32(data, offset)
		record['time3'], offset      = self._decodeUint32(data, offset)
		record['filelength'], offset = self._decodeUint64(data, offset)
		record['flag'], offset       = self._decodeUint8(data, offset)
		numProperties, offset = self._decodeUint8(data, offset)
		record['properties'] = {}
		for x in range(numProperties):
			prop, offset = self._decodeString(data, offset)
			value, offset = self._decodeString(data, offset)
			record['properties'][prop] = value
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
			return ('', offset + 2)
		length, offset = self._decodeUint16(data, offset)
		string = data[offset:offset+length]
		return (string, offset + length)

if __name__ == '__main__':
	import os, sys
	backup_folder = os.path.join(os.path.expanduser('~'), 'Library/Application Support/MobileSync/Backup/')
	backups = sorted(os.listdir(backup_folder), key=lambda x: os.path.getmtime(os.path.join(backup_folder, x)))

	for i, f in enumerate(backups):
		print '%d: %s' % (i, f)
	choice = raw_input('select backup: ')

	if choice:
		try:
			choice = int(choice)
		except ValueError:
			print 'choice must be a number'
			sys.exit(1)
		
		try:
			backup = backups[choice]
		except IndexError:
			print 'invalid choice'
			sys.exit(1)
	else:
		backup = backups[-1]

	mbdb = ManifestMBDB(os.path.join(backup_folder, backup, 'Manifest.mbdb'))
	print mbdb.version

	for rec in mbdb:
		print rec['domain'], rec['path']

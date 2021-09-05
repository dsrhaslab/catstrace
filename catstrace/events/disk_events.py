from catstrace.events.base_event import Event, EventType
import simplejson as json
import codecs

class DiskEvent(Event):
	def __init__(self, timestamp, host, pid, filename, fd):
		self._fd = fd

		if (fd == 0): self._filename = "STDIN"
		elif (fd == 1): self._filename = "STDOUT"
		elif (fd == 2): self._filename = "STDERR"
		else: self._filename = filename

		super(DiskEvent, self).__init__(timestamp, host, pid)


class DiskOpenEvent(DiskEvent):
	def __init__(self, timestamp, host, pid, filename, fd):
		self._type = EventType.DISK_OPEN
		super(DiskOpenEvent, self).__init__(timestamp, host, pid, filename, fd)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"data": {
                "host": self._host
			},
			"fd": self._fd,
			"filename": self._filename,
		}
		return event

	def to_json(self):
		return json.dumps(self.to_string())

class DiskWriteEvent(DiskEvent):
	def __init__(self, timestamp, host, pid, filename, fd, offset, size, returned_value, msg, saveAsText):
		self._type = EventType.DISK_WRITE

		self._offset = offset
		self._size = size
		self._returned_value = returned_value
		self._msg = codecs.unicode_escape_decode(msg)[0]
		self._msg_len = len(self._msg)

		if not saveAsText:
			self._signature = self.compute_minhashes(self._msg, self._msg_len)
			self._msg_len = -1

		super(DiskWriteEvent, self).__init__(timestamp, host, pid, filename, fd)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"size": self._size,
			"returned_value": self._returned_value,
			"data": {
                "host": self._host
			},
		}
		if (self._fd is not None): event["fd"] = self._fd
		if (self._offset is not None): event["offset"] = self._offset
		if (self._filename is not None): event["filename"] = self._filename
		if (self._msg_len != -1):
			event["data"]["msg"] = self._msg
			event["data"]["msg_len"] = self._msg_len
		else:
			event["data"]["signature"] = self._signature

		return event

	def to_json(self):
		return json.dumps(self.to_string())

class DiskReadEvent(DiskEvent):
	def __init__(self, timestamp, host, pid, filename, fd, offset, size, returned_value, msg, saveAsText):
		self._type = EventType.DISK_READ

		self._offset = offset
		self._size = size
		self._returned_value = returned_value
		self._msg = codecs.unicode_escape_decode(msg)[0]
		self._msg_len = len(self._msg)

		if not saveAsText:
			self._signature = self.compute_minhashes(self._msg, self._msg_len)
			self._msg_len = -1

		super(DiskReadEvent, self).__init__(timestamp, host, pid, filename, fd)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"size": self._size,
			"returned_value": self._returned_value,
			"data": {
                "host": self._host
			},
		}
		if (self._fd is not None): event["fd"] = self._fd
		if (self._offset is not None): event["offset"] = self._offset
		if (self._filename is not None): event["filename"] = self._filename
		if (self._msg_len != -1):
			event["data"]["msg"] = self._msg
			event["data"]["msg_len"] = self._msg_len
		else:
			event["data"]["signature"] = self._signature

		return event

	def to_json(self):
		return json.dumps(self.to_string())
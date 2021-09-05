from catstrace.events.base_event import Event, EventType
import simplejson as json
import codecs

class SocketEvent(Event):
	def __init__(self, timestamp, host, pid, socket_type, sport, dport, saddr, daddr):
		self._sport = sport
		self._dport = dport
		self._saddr = saddr
		self._daddr = daddr
		self._socket_type = socket_type
		self._socket = self._generate_socket_id(saddr, daddr, sport, dport)
		super(SocketEvent, self).__init__(timestamp, host, pid)

	@staticmethod
	def _generate_socket_id(addr1, addr2, port1, port2):
		if addr1 < addr2:
			socket_id = "%s:%d-%s:%d" % (addr1, port1, addr2, port2)
		elif addr2 < addr1:
			socket_id = "%s:%d-%s:%d" % (addr2, port2, addr1, port1)
		else:
			if port1 < port2:
				socket_id = "%s:%d-%s:%d" % (addr1, port1, addr2, port2)
			else:
				socket_id = "%s:%d-%s:%d" % (addr2, port2, addr1, port1)

		return socket_id

class SocketConnect(SocketEvent):
	def __init__(self, timestamp, host, pid, socket_type, sport, dport, saddr, daddr):
		self._type = EventType.SOCKET_CONNECT
		super(SocketConnect, self).__init__(timestamp, host, pid, socket_type, sport, dport, saddr, daddr)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"socket": self._socket,
			"socket_type": self._socket_type,
			"src": self._saddr,
			"src_port": self._sport,
			"dst": self._daddr,
			"dst_port": self._dport,
			"data": {
                "host": self._host
			},
		}
		return event

	def to_json(self):
		return json.dumps(self.to_string())

class SocketAccept(SocketEvent):
	def __init__(self, timestamp, host, pid, socket_type, sport, dport, saddr, daddr):
		self._type = EventType.SOCKET_ACCEPT
		super(SocketAccept, self).__init__(timestamp, host, pid, socket_type, sport, dport, saddr, daddr)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"socket": self._socket,
			"socket_type": self._socket_type,
			"src": self._saddr,
			"src_port": self._sport,
			"dst": self._daddr,
			"dst_port": self._dport,
			"data": {
                "host": self._host
			},
		}
		return event

	def to_json(self):
		return json.dumps(self.to_string())

class SocketSend(SocketEvent):
	def __init__(self, timestamp, host, pid, socket_type, sport, dport, saddr, daddr, size, returned_value, msg, text):
		self._type = EventType.SOCKET_SEND

		self._size = size
		self._returned_value = returned_value
		self._msg = codecs.unicode_escape_decode(msg)[0]
		self._msg_len = len(self._msg)

		if not text:
			self._signature = self.compute_minhashes(self._msg, self._msg_len)
			self._msg_len = -1

		super(SocketSend, self).__init__(timestamp, host, pid, socket_type, sport, dport, saddr, daddr)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"socket": self._socket,
			"socket_type": self._socket_type,
			"src": self._saddr,
			"src_port": self._sport,
			"dst": self._daddr,
			"dst_port": self._dport,
			"size": self._size,
			"returned_value": self._returned_value,
			"data": {
                "host": self._host
			},

		}
		if (self._msg_len != -1):
			event["data"]["msg"] = self._msg
			event["data"]["msg_len"] = self._msg_len
		else:
			event["data"]["signature"] = self._signature

		return event

	def to_json(self):
		return json.dumps(self.to_string())

class SocketReceive(SocketEvent):
	def __init__(self, timestamp, host, pid, socket_type, sport, dport, saddr, daddr, size, returned_value, msg, text):
		self._type = EventType.SOCKET_RECEIVE

		self._size = size
		self._returned_value = returned_value
		self._msg = codecs.unicode_escape_decode(msg)[0]
		self._msg_len = len(self._msg)

		if not text:
			self._signature = self.compute_minhashes(self._msg, self._msg_len)
			self._msg_len = -1

		super(SocketReceive, self).__init__(timestamp, host, pid, socket_type, sport, dport, saddr, daddr)

	def to_string(self):
		event = {
			"timestamp": self._timestamp,
			"type": self._type,
			"thread": self._thread,
			"pid": self._pid,
			"socket": self._socket,
			"socket_type": self._socket_type,
			"src": self._saddr,
			"src_port": self._sport,
			"dst": self._daddr,
			"dst_port": self._dport,
			"size": self._size,
			"returned_value": self._returned_value,
			"data": {
                "host": self._host
			},
		}

		if (self._msg_len != -1):
			event["data"]["msg"] = self._msg
			event["data"]["msg_len"] = self._msg_len
		else:
			event["data"]["signature"] = self._signature

		return event

	def to_json(self):
		return json.dumps(self.to_string())
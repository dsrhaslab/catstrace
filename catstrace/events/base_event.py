import ctypes
import numpy as np
from lsh import minhash # https://github.com/mattilyra/lsh

import binascii

TASK_COMM_LEN = 16  # linux/sched.h

class EventType():
	SOCKET_SEND = 8
	SOCKET_RECEIVE = 9
	SOCKET_CONNECT = 11
	SOCKET_ACCEPT = 12

	PROCESS_CREATE = 1
	PROCESS_START = 2
	PROCESS_END = 3
	PROCESS_JOIN = 4

	FSYNC = 13

	DISK_WRITE = 21
	DISK_READ = 22
	DISK_OPEN = 23

	@staticmethod
	def is_socket(type):
		return type == EventType.SOCKET_SEND or \
			type == EventType.SOCKET_RECEIVE or \
			type == EventType.SOCKET_CONNECT or \
			type == EventType.SOCKET_ACCEPT

	@staticmethod
	def is_process(type):
		return type == EventType.PROCESS_CREATE or \
			type == EventType.PROCESS_START or \
			type == EventType.PROCESS_END or \
			type == EventType.PROCESS_JOIN or \
			type == EventType.FSYNC

	@staticmethod
	def is_disk(type):
		return type == EventType.DISK_WRITE or \
			type == EventType.DISK_READ or \
			type == EventType.DISK_OPEN

	@staticmethod
	def name(type):
		if type == EventType.SOCKET_SEND: return "sock_send"
		elif type == EventType.SOCKET_RECEIVE: return "sock_receive"
		elif type == EventType.SOCKET_CONNECT: return "sock_connect"
		elif type == EventType.SOCKET_ACCEPT: return "sock_accept"
		elif type == EventType.PROCESS_CREATE: return "process_create"
		elif type == EventType.PROCESS_START: return "process_start"
		elif type == EventType.PROCESS_END: return "process_end"
		elif type == EventType.PROCESS_JOIN: return "process_join"
		elif type == EventType.FSYNC: return "fsync"
		elif type == EventType.DISK_OPEN: return "disk_open"
		elif type == EventType.DISK_WRITE: return "disk_write"
		elif type == EventType.DISK_READ: return "disk_read"

class Event(object):
	event_counter = 0

	def __init__(self, timestamp, host, pid):
		self._timestamp = timestamp
		self._host = host
		self._pid = pid
		self._thread = "%d@%s" % (pid, host)

	def to_string(self):
		return NotImplemented

	def to_json(self):
		return NotImplemented

	def to_bytes(self):
		return NotImplemented

	@staticmethod
	def compute_minhashes(message, mlen):
		if (mlen <= 0): return []
		seeds = np.array([ 82241,  37327, 892129, 314275, 984838, 268169, 654205, 386536,  43381, 745416])
		hasher = minhash.MinHasher(seeds=seeds, char_ngram=5, hashbytes=8)
		return hasher.fingerprint(message).tolist()

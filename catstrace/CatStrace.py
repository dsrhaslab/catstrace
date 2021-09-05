import argparse
import os
import re
import sys
import json
import codecs
import pkg_resources
import socket
import queue
import logging
import logging.config
import ctypes
import datetime
import fcntl
import signal
import ntpath
from catstrace.json_transformer import to_json
from catstrace.events.base_event import Event, EventType
from catstrace.events.disk_events import DiskOpenEvent, DiskReadEvent, DiskWriteEvent
from catstrace.events.socket_events import SocketEvent, SocketConnect, SocketAccept, SocketReceive, SocketSend
from multiprocessing import Process, Manager, Value, Queue, Event, Lock, current_process
from importlib.resources import read_text
from setproctitle import setproctitle
from functools import partial
from pprint import pprint
from lark import Lark



# Configure logger
logging.config.fileConfig(pkg_resources.resource_filename('catstrace', 'logging.ini'))

######################################################

class CatStrace():

	def __init__(self, filename, host, host_ip, cmd, pid, esize, whitelist=None, stats=False, saveAsText=False, output=None):
		self._whitelistfile = whitelist
		self._print_stats = stats
		self._capture_size = esize
		self._nProducers = 4
		self._nConsumers = 4

		# Init Lark parser
		grammar_file = pkg_resources.resource_filename('catstrace', 'grammar.lark')
		grammar = open(grammar_file).read()

		# If live mode on prepar named pipe
		if filename is None:
			self._run_tracer = True
			self._filename = "/tmp/strace_pipe"
			if os.path.exists(self._filename): os.remove(self._filename)
			try:
				os.mkfifo(self._filename)
			except OSError as e:
				logging.error("Failed to create STRACE FIFO: %s" % e)
				os._exit(1)

			if pid is None:
				self._program_pid = run_program_cmd(self._filename, self._capture_size, cmd)
			else:
				self._program_pid = run_program_pid(self._filename, self._capture_size, pid)
		else:
			self._run_tracer = False
			self._filename = filename
			self._program_pid = None

		# Create output files
		if (output is not None):
			self._output_file = open(output, "w", encoding='utf8')
		else:
			self._output_file = open("CATlog.json", "w", encoding='utf8')
		self._stats_filename = "CatStrace-stats.json"


		# Variables and auxiliary structures
		self._stack = {} # stack with unfinished syscall
		manager = Manager()
		self._whitelist = manager.list() # list of paths to consider
		self._sockets_info = manager.dict() # info of open sockets
		self._host = manager.Value(ctypes.c_char_p, host)
		self._host_ip = manager.Value(ctypes.c_char_p, host_ip)
		self._events_traced = manager.dict() # for stats
		self._lock_events_traced = Lock()
		self._events_saved = manager.dict() # for stats
		self._lock_events_saved = Lock()
		self._saveAsText = manager.Value(ctypes.c_bool, saveAsText)
		self._inputs_queue = Queue(1000)
		self._events_queue = Queue()
		self._stop_handler = Event()
		self._stop_flusher = Event()
		self._handler_finished = Event()
		self._handler_unhandled_events = []

		self._cmd = cmd
		self._events_lost = 0
		self._truncated = 0

		self._strace_elapsed_time = 0

		# Prepare handlers processes
		self._handlers = []
		for i in range(0, self._nProducers):
			unhandled_events = manager.Value('i', 0)
			self._handler_unhandled_events.append(unhandled_events)
			self._handlers.append(Process(name='handler'+str(i), target=handle_event, args=(grammar, self._inputs_queue, self._events_queue,  self._stop_handler, self._sockets_info, self._whitelist,  self._host, self._saveAsText, self._events_traced, self._lock_events_traced, unhandled_events,)))

		# Prepare flushers processes
		self._flushers = []
		for i in range(0, self._nConsumers):
			self._flushers.append(Process(name='flusher'+str(i), target=flush_event, args=(self._output_file, self._events_queue, self._stop_flusher, self._handler_finished, self._sockets_info, self._host_ip, self._capture_size, self._events_saved, self._lock_events_saved,)))

	def run(self):

		# Load whitelist
		if self._whitelistfile is not None:
			logging.info("Loading whitelistfile " + str(self._whitelistfile) + "...")
			self._load_white_list()

		if (self.print_stats): logging.info("Stats On...")
		logging.info("Capture size = %d" % self._capture_size)

		# Start flushers
		for i in range(0, self._nConsumers):
			self._flushers[i].start()

		# Start handlers
		for i in range(0, self._nProducers):
			self._handlers[i].start()

		start_sparser_ts = datetime.datetime.now()

		# parse input file
		logging.info("Parsing strace output...")
		self.parse_file()

		if (self._run_tracer):
			logging.info("Strace Execution Time was %d ms." % (self._strace_elapsed_time))

		# Stop handlers
		self._stop_handler.set()
		logging.info("Stop handler set...")
		for i in range(0, self._nProducers):
			self._handlers[i].join()
		self._handler_finished.set()
		logging.info("All handlers have finished.")

		# Stop flushers
		self._stop_flusher.set()
		for i in range(0, self._nConsumers):
			self._flushers[i].join()
		logging.info("All flushers have finished.")
		self._output_file.flush()
		self._output_file.close()

		end = datetime.datetime.now()
		self._parser_elapsed_time = (end - start_sparser_ts).total_seconds() * 1000
		logging.info("CatStrace Execution Time was %d ms." % (self._parser_elapsed_time))

		if (self._print_stats): self.print_stats()

		# if live mode on remove named pipe
		if (self._run_tracer): os.remove(self._filename)

		sys.exit()

	def parse_file(self):

		if (self._run_tracer):
			signal.signal( signal.SIGINT, lambda signal, frame: self._signal_handler() )
			signal.signal( signal.SIGCHLD, lambda signal, frame: self._received_child_exit() )
			self._program_start_ts = datetime.datetime.now()
			os.kill(self._program_pid, signal.SIGCONT)

		logging.info("Parsing file %s" % (self._filename))
		file = open(self._filename, "r")
		if (self._run_tracer):
			F_SETPIPE_SZ = 1031  # Linux 2.6.35+
			F_GETPIPE_SZ = 1032  # Linux 2.6.35+
			# logging.info("Pipe size		: "+str(fcntl.fcntl(file, F_GETPIPE_SZ)))
			fcntl.fcntl(file, F_SETPIPE_SZ, 3000000)
			# logging.info("Pipe (modified) size : "+str(fcntl.fcntl(file, F_GETPIPE_SZ)))

		self._total_unfinished_syscalls = 0
		self._total_strace_events = 0
		self._total_events = 0
		for line in file:
			self._total_strace_events += 1

			if re.search(r"\<unfinished\s\.\.\.\>", line):
				a = re.split(r"\s+", line, 1)
				pid = int(a[0])
				self._stack.setdefault(pid,[]).append(line)
				self._total_unfinished_syscalls += 1
			elif re.search(r"resumed\>", line):
				a = re.split(r"\s+", line, 1)
				pid = int(a[0])
				unfinished_syscall = self._stack[pid].pop()
				self._put_input_queue((line, unfinished_syscall))
			else:
				self._put_input_queue((line, None))

			if self._total_strace_events % 1000000 == 0:
				logging.info("Loaded %d strace events" %(self._total_strace_events))


	def print_stats(self):

		stats_dict = {
			"command": " ".join(self._cmd),
			"target_pid": self._program_pid,
			"input_file": self._filename,
			"strace_elapsed_time": self._strace_elapsed_time,
			"parser_elapsed_time": self._parser_elapsed_time,
			"events": {
				"process": {
				"saved": 0,
				"truncated": 0,
				},
				"network": {
					"saved": 0,
					"truncated": 0,
				},
				"disk": {
					"saved": 0,
					"truncated": 0,
				},
				"total": {
					"strace_entries": self._total_strace_events,
					"handled_events": self._total_events,
					"lost_events": self._events_lost,
					"saved_events": 0,
					"truncated_events": 0,
					"unhandled_events": 0,
					"discarded_events": 0,
					"errors_events": 0,
					"unfinished_events": self._total_unfinished_syscalls,
				}
			},
		}

		if (self._run_tracer):
			del stats_dict["input_file"]
			if (self._cmd is None):
				del stats_dict["command"]
			else:
				del stats_dict["target_pid"]
		else:
			del stats_dict["command"]
			del stats_dict["target_pid"]
			del stats_dict["strace_elapsed_time"]

		for unhandled_events in self._handler_unhandled_events:
			stats_dict["events"]["total"]["unhandled_events"] += unhandled_events.value

		logging.info("Strace Events:")
		logging.info("\t%-15s\t%5s\t%7s\t%6s\t%9s", "Syscall", "Calls", "Returns", "Errors", "Discarded")
		stats_dict["strace_syscalls"] = []
		for key, value in self._events_traced.items():
			stats_dict["events"]["total"]["discarded_events"] += value["discarded"]
			stats_dict["events"]["total"]["errors_events"] += value["errors"]
			logging.info("\t%-10s\t%5d\t%5d\t%5d\t%5d", key, value["calls"], value["saved"], value["errors"], value["discarded"])
			syscall_stats = {
				"syscall": key,
				"calls": value["calls"],
				"returns": value["saved"],
				"errors": value["errors"],
				"discarded": value["discarded"]
			}
			stats_dict["strace_syscalls"].append( syscall_stats )

		if len(self._events_saved) > 0:
			logging.info("StraceParser Events:")
			logging.info("\t%-15s\t%6s\t%7s", "Type", "Saved", "Truncated")
			for key, value in self._events_saved.items():
				logging.info("\t%-15s\t%6d\t%7d" % (EventType.name(key), value["saved"], value["truncated"]))
				stats_dict["events"]["total"]["saved_events"] += value["saved"]
				stats_dict["events"]["total"]["truncated_events"] += value["truncated"]
				if EventType.is_process(key):
					stats_dict["events"]["process"]["saved"] += value["saved"]
					stats_dict["events"]["process"]["truncated"] += value["truncated"]
				elif EventType.is_socket(key):
					stats_dict["events"]["network"]["saved"] += value["saved"]
					stats_dict["events"]["network"]["truncated"] += value["truncated"]
				elif EventType.is_disk(key):
					stats_dict["events"]["disk"]["saved"] += value["saved"]
					stats_dict["events"]["disk"]["truncated"] += value["truncated"]

		logging.info("STRACE EVENTS: \t%d" % (self._total_strace_events))
		logging.info("-UNFINISHED EVENTS: \t%d" % (self._total_unfinished_syscalls))
		logging.info("-HANDLED EVENTS: \t%d" % (self._total_events))
		logging.info("--LOST EVENTS: \t%d" % (self._events_lost))
		logging.info("--SAVED EVENTS: \t%d" % (stats_dict["events"]["total"]["saved_events"]))
		logging.info("  TRUNCATED EVENTS: \t%d" % (stats_dict["events"]["total"]["truncated_events"]))
		logging.info("--UNHANDLED EVENTS: \t%d" % (stats_dict["events"]["total"]["unhandled_events"]))
		logging.info("--DISCARDED EVENTS: \t%d" % (stats_dict["events"]["total"]["discarded_events"]))
		logging.info("--ERRORS EVENTS: \t%d" % (stats_dict["events"]["total"]["errors_events"]))


		with open(self._stats_filename, 'w') as stats_file:
			json.dump(stats_dict, stats_file, indent=4)

	def _signal_handler(self):
		os.kill(self._program_pid, signal.SIGINT)

	def _received_child_exit(self):
		pid, _ = os.waitpid(-1, os.WNOHANG)
		if pid == self._program_pid:
			end = datetime.datetime.now()
			self._strace_elapsed_time = (end - self._program_start_ts).total_seconds() * 1000

	def _put_input_queue(self, data):
		try:
			if self._run_tracer:
				self._inputs_queue.put(data, False)
			else:
				self._inputs_queue.put(data, True)
		except queue.Full:
			self._events_lost += 1
		self._total_events += 1

	def _load_white_list(self):
		with open(self._whitelistfile) as fp:
			lines = fp.read().splitlines()
			for line in lines:
				self._whitelist.append(line)

######################################################

def handle_event(grammar, inputs_queue, events_queue, stop_handler, sockets_info, whitelist, host, saveAsText, events_traced, lock, unhandled_events):
	setproctitle("CatStrace-handler")
	def ignore(signal, frame): return
	signal.signal(signal.SIGINT, ignore)
	parser = Lark(grammar)

	while True:

		try:
			(syscall_line, unfinished_syscall_line) = inputs_queue.get(True, timeout=5)

			tree = parser.parse(syscall_line)
			syscall = to_json(tree)
			if (unfinished_syscall_line is not None):
				tree = parser.parse(unfinished_syscall_line)
				unfinished_syscall = to_json(tree)
			else:
				unfinished_syscall = None

			if (syscall["type"] not in ["syscall", "resumed_syscall"]):
				unhandled_events.value += 1
				continue

			_increment_call_handled_events_stats(events_traced, syscall["name"], lock)
			event = None

			if syscall["result"]["type"] == "r_error":
				_increment_error_handled_events_stats(events_traced, syscall["name"], lock)
				continue

			if syscall["name"] == "socket":
				_handle_socket_syscall(sockets_info, syscall)
			elif syscall["name"] == "connect":
				event = _handle_connect_syscall(sockets_info, host, syscall)
			elif syscall["name"] in ["accept", "accept4"]:
				event = _handle_accept_syscall(sockets_info, host, syscall)
			elif syscall["name"] in ["send", "recv", "sendto", "recvfrom"]:
				event = _handle_send_to_recv_from_syscall(sockets_info, host, saveAsText, syscall)
			elif syscall["name"] in ["sendmsg", "recvmsg"]:
				event = _handle_sendmsg_recvmsg_syscall(sockets_info, host, saveAsText, syscall)
			elif syscall["name"] in ["read", "pread64"]:
				event = _handle_read_syscall(sockets_info, host, saveAsText, syscall, unfinished_syscall)
			elif syscall["name"] in  ["write", "pwrite64"]:
				event = _handle_write_syscall(sockets_info, host, saveAsText, syscall, unfinished_syscall)
			elif syscall["name"] == "open" or syscall["name"] == "openat":
				event = _handle_open_syscall(host, syscall, unfinished_syscall)
			else:
				logging.info("unhandled syscall: " + syscall["name"])
				unhandled_events.value += 1
				continue

			try:
				if (not _discard_event(whitelist, event)):
					events_queue.put(event, False)
					_increment_saved_handled_events_stats(events_traced, syscall["name"], lock)
				else:
					_increment_discarded_handled_events_stats(events_traced, syscall["name"], lock)
			except queue.Full:
				logging.info("Events Queue is Full!!!")

		except queue.Empty:
			if (stop_handler.is_set() and inputs_queue.empty()):
				break
			else:
				continue

def flush_event(output_file, events_queue, stop_flusher, handler_finished, sockets_info, host_ip, capture_size, events_saved, lock):
	setproctitle("CatStrace-flusher")
	def ignore(signal, frame): return
	signal.signal(signal.SIGINT, ignore)

	events_written = 0
	while True:

		try:
			event = events_queue.get(True, timeout=5)
			# update SOCKET_CONNECT events info
			if event._type == EventType.SOCKET_CONNECT:
				if event._fd in sockets_info and "src" in sockets_info[event._fd]:
					event._saddr = sockets_info[event._fd]["src"]
					event._sport = sockets_info[event._fd]["src_port"]
					event._socket = SocketEvent._generate_socket_id(event._saddr, event._daddr, event._sport, event._dport)
				else:
					if (events_queue.empty() and handler_finished.is_set()):
						event._saddr = host_ip.value
						event._sport = 0
						event._socket = SocketEvent._generate_socket_id(event._saddr, event._daddr, event._sport, event._dport)
					else:
						events_queue.put(event)
						continue

			if hasattr(event, '_returned_value') and event._returned_value > capture_size:
				_increment_truncated_events_stats(events_saved, event._type, lock)
			output_file.write(event.to_json() + os.linesep)
			_increment_saved_events_stats(events_saved, event._type, lock)
			events_written += 1
			if (events_written % 1000 == 0):
				output_file.flush()

		except queue.Empty:
			if (stop_flusher.is_set() and events_queue.empty()):
				output_file.flush()
				break
			else:
				continue

######################################################

def _handle_socket_syscall(sockets_info, syscall):
	if (syscall["result"]["type"] == "file_descriptor"):
		fd = syscall["result"]["fd"]
		path = syscall["result"]["path"]

		if (fd not in sockets_info):
			fd_dict = {}
		else:
			fd_dict = sockets_info[fd]
		fd_dict["ino_number"] = path["ino_number"]
		sockets_info[fd] = fd_dict

def _handle_connect_syscall(sockets_info, host, syscall):
		# 1486935 06:47:16.058866 connect(40<TCPv6:[136131809]>, {sa_family=AF_INET6, sin6_port=htons(2181), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:192.168.112.120", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)
		socket_type = None
		family = None
		dst_addr = None
		dst_port = None
		for arg in syscall["args"]:
			if arg["type"] == "file_descriptor":
				fd = arg["fd"]
				path = arg["path"]
				socket_type = path["socket_type"]
				ino_number = path["ino_number"]
			elif arg["type"] == "braced":
				for barg in arg["value"]:
					if barg["type"] == "key_value":
						if barg["key"] == "sa_family":
							family = barg["value"]["value"]
						if barg["key"] == "sin_port" or barg["key"] == "sin6_port":
							dst_port = int(barg["value"]["args"][0]["value"])
						if barg["key"] == "sin_addr":
							dst_addr = barg["value"]["args"][0]["value"]
					elif barg["type"] == "function":
						if barg["name"] == "inet_pton":
							dst_addr = barg["args"][1]["value"]

		# logging.info("FD: ", fd, ", socket_type: ", socket_type, ", ino_number: ", ino_number, ", dst_addr: ", dst_addr, ", dst_port: ", dst_port)

		if (family == 'AF_INET' or family == 'AF_INET6'):
			if fd in sockets_info:
				fd_dict = sockets_info[fd]
			else:
				fd_dict = {}
			if 'dst' in fd_dict and fd_dict['dst'] == dst_addr and\
				'dst_port' in fd_dict and fd_dict['dst_port'] == dst_port:
				if 'ino_number' not in fd_dict: fd_dict['ino_number'] = ino_number
			else:
				fd_dict['dst'] = dst_addr
				fd_dict['dst_port'] = dst_port
			sockets_info[fd] = fd_dict

			event = SocketConnect(syscall["timestamp"], host.value, syscall["pid"], socket_type, 0, dst_port, "", dst_addr)
			event._fd = fd
			return event
			# logging.info(event.to_string())

def _handle_accept_syscall(sockets_info, host, syscall):
	# int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	# int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

	event = None
	timestamp = syscall["timestamp"]
	pid = syscall["pid"]

	# arg_sockfd = syscall["args"][0]
	# arg_addr = syscall["args"][1]["value"]
	# arg_addrlen = syscall["args"][2]["value"]
	# if accept4:
	# 	arg_flags = syscall["args"][3]["value"]

	result = syscall["result"]
	if (result["type"] == "file_descriptor"):
		if result["path"]["socket_type"] not in ["TCP", "UDP", "TCPv6"]: return None
		fd, socket_type, src, src_port, dst, dst_port = _get_socket_info(result)


		src, dst = dst, src
		src_port, dst_port = dst_port, src_port

		if fd in sockets_info:
			fd_dict = sockets_info[fd]
			fd_dict['src'] = src
			fd_dict['src_port'] = src_port
			fd_dict['dst'] = dst
			fd_dict['dst_port'] = dst_port
			sockets_info[fd] = fd_dict

		event = SocketAccept(timestamp, host.value, pid, socket_type, src_port, dst_port, src, dst)

	return event

def _handle_send_to_recv_from_syscall(sockets_info, host, saveAsText, syscall):
	# ssize_t send(int sockfd, const void *buf, size_t len, int flags);
	# ssize_t recv(int sockfd, void *buf, size_t len, int flags);
	# ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	# 			   const struct sockaddr *dest_addr, socklen_t addrlen);
	# ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
    #                  struct sockaddr *src_addr, socklen_t *addrlen)
	event = None
	timestamp = syscall["timestamp"]
	pid = syscall["pid"]

	arg_sockfd = syscall["args"][0]
	arg_buf = syscall["args"][1]["value"]
	arg_len = syscall["args"][2]["value"]
	# arg_flags = syscall["args"][3]
	# arg_addr = syscall["args"][4]
	# arg_addrlen = syscall["args"][5]

	if arg_sockfd["path"]["type"] != "socket_path": return None

	result = syscall["result"]
	if (result["type"] == "number"):
		returned_value = int(result["value"])
		event = _handle_socket_send_recv(sockets_info, host.value, timestamp, pid, syscall["name"], arg_sockfd, arg_len, returned_value, arg_buf, saveAsText.value)
	return event

def _handle_sendmsg_recvmsg_syscall(sockets_info, host, saveAsText, syscall):
	# ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
	# ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
	event = None
	timestamp = syscall["timestamp"]
	pid = syscall["pid"]

	arg_sockfd = syscall["args"][0]
	arg_msg = syscall["args"][1]["value"]
	arg_flags = syscall["args"][2]["value"]

	if arg_sockfd["path"]["type"]  == "local_socket_path":
		if arg_sockfd["path"]["socket_type"] not in ["TCP", "UDP", "TCPv6"]: return None
		assert arg_msg[0]["value"]["value"][0]["key"] == "sa_family"
		family = arg_msg[0]["value"]["value"][0]["value"]["value"]
		assert arg_msg[0]["value"]["value"][1]["key"] == "sin_port"
		dst_port = arg_msg[0]["value"]["value"][1]["value"]["args"][0]["value"]
		assert arg_msg[0]["value"]["value"][2]["key"] == "sin_addr"
		dst_addr = arg_msg[0]["value"]["value"][2]["value"]["args"][0]["value"]

		if family != "AF_INET" and family != "AF_INET6": return None
		arg_sockfd["path"]["type"] = "socket_path"
		arg_sockfd["path"]["dst"] = dst_addr
		arg_sockfd["path"]["dst_port"] = dst_port

	if arg_sockfd["path"]["type"] != "socket_path": return None

	assert arg_msg[2]["key"] == "msg_iov"
	arg_msg_iov = arg_msg[2]["value"]["value"][0]["value"]
	assert arg_msg_iov[0]["key"] == "iov_base"
	iov_base = arg_msg_iov[0]["value"]["value"]
	assert arg_msg_iov[1]["key"] == "iov_len"
	iov_len = arg_msg_iov[1]["value"]["value"]

	result = syscall["result"]
	if (result["type"] == "number"):
		returned_value = int(result["value"])
		event = _handle_socket_send_recv(sockets_info, host.value, timestamp, pid, syscall["name"], arg_sockfd, iov_len, returned_value, iov_base, saveAsText.value)
	return event

def _handle_read_syscall(sockets_info, host, saveAsText, syscall, unfinished_syscall=None):
	event = None
	offset = None
	pid = syscall["pid"]

	if (unfinished_syscall is not None):
		timestamp = unfinished_syscall["timestamp"]
		file_descriptor = unfinished_syscall["args"][0]
		buffer = syscall["args"][0]["value"]
		size = int(syscall["args"][1]["value"])
		if (syscall == "pread64"): offset = int(syscall["args"][2]["value"])
	else:
		timestamp = syscall["timestamp"]
		file_descriptor = syscall["args"][0]
		buffer = syscall["args"][1]["value"]
		size = int(syscall["args"][2]["value"])
		if (syscall == "pread64"): offset = int(syscall["args"][3]["value"])

	result = syscall["result"]
	if (result["type"] == "number"):
		returned_value = int(result["value"])

	if file_descriptor["path"]["type"] == "socket_path" or file_descriptor["path"]["type"] == "socket_ino_path":
		event = _handle_socket_send_recv(sockets_info, host.value, timestamp, pid, syscall["name"], file_descriptor, size, returned_value, buffer, saveAsText.value)
	elif file_descriptor["path"]["type"] == "file_path":
		event = _handle_disk_write_read(host.value, timestamp, pid, syscall["name"], file_descriptor, offset, size, returned_value, buffer, saveAsText.value)
	else:
		logging.info("ERROR parsing syscall read " + file_descriptor)

	return event

def _handle_write_syscall(sockets_info, host, saveAsText, syscall, unfinished_syscall=None):
	event = None
	offset = None
	pid = syscall["pid"]

	if (unfinished_syscall is not None):
		timestamp = unfinished_syscall["timestamp"]
		file_descriptor = unfinished_syscall["args"][0]
		buffer = unfinished_syscall["args"][1]["value"]
		size = int(unfinished_syscall["args"][2]["value"])
		if (syscall == "pwrite64"): offset = int(unfinished_syscall["args"][3]["value"])
	else:
		timestamp = syscall["timestamp"]
		file_descriptor = syscall["args"][0]
		buffer = syscall["args"][1]["value"]
		size = int(syscall["args"][2]["value"])
		if (syscall == "pwrite64"): offset = int(syscall["args"][3]["value"])

	result = syscall["result"]
	if (result["type"] == "number"):
		returned_value = int(result["value"])

	if file_descriptor["path"]["type"] == "socket_path" or file_descriptor["path"]["type"] == "socket_ino_path":
		event = _handle_socket_send_recv(sockets_info, host.value, timestamp, pid, syscall["name"], file_descriptor, size, returned_value, buffer, saveAsText.value)
	elif file_descriptor["path"]["type"] == "file_path":
		event = _handle_disk_write_read(host.value, timestamp, pid, syscall["name"], file_descriptor, offset, size, returned_value, buffer, saveAsText.value)
	else:
		logging.info("ERROR parsing syscall write " + file_descriptor)

	return event

def _handle_open_syscall(host, syscall, unfinished_syscall=None):
	event = None
	timestamp = syscall["timestamp"]
	pid = syscall["pid"]
	if (syscall["result"]["type"] == "file_descriptor"):
		fd = syscall["result"]["fd"]
		filepath = syscall["result"]["path"]["value"]
		event = DiskOpenEvent(timestamp, host.value, pid, filepath, fd)
	# else: # TODO: save errors??
	return event

######################################################

def _get_socket_info(file_descriptor):

	fd = int(file_descriptor["fd"])
	socket_type = file_descriptor["path"]["socket_type"]
	src = file_descriptor["path"]["src"]
	src_port = int(file_descriptor["path"]["src_port"])
	dst = file_descriptor["path"]["dst"]
	dst_port  = int(file_descriptor["path"]["dst_port"])

	return fd, socket_type, src, src_port, dst, dst_port

def _handle_socket_send_recv(sockets_info, host, timestamp, pid, syscall, file_descriptor, size, r_value, buffer, saveAsText):
	event = None

	if file_descriptor["path"]["socket_type"] not in ["TCP", "UDP", "TCPv6"]: return None
	fd, socket_type, src, src_port, dst, dst_port = _get_socket_info(file_descriptor)

	if fd in sockets_info:
		fd_dict = sockets_info[fd]
	else:
		fd_dict = {}
	fd_dict['src'] = src
	fd_dict['src_port'] = src_port
	fd_dict['dst'] = dst
	fd_dict['dst_port'] = dst_port
	sockets_info[fd] = fd_dict

	if syscall == "pread64": logging.info("WARNING: pread64 -> send unhandled")
	if syscall == "read" or syscall == "recv" or syscall == "recvfrom" or  syscall == "recvmsg":
		src, dst = dst, src
		src_port, dst_port = dst_port, src_port
		event = SocketReceive(timestamp, host, pid, socket_type, src_port, dst_port, src, dst, size, r_value, buffer, saveAsText)
	elif syscall == "write" or syscall == "send" or syscall == "sendto" or syscall == "sendmsg":
		event = SocketSend(timestamp, host, pid, socket_type, src_port, dst_port, src, dst, size, r_value, buffer, saveAsText)

	return event

def _handle_disk_write_read(host, timestamp, pid, syscall, file_descriptor, offset, size, r_value, buffer, saveAsText):
		event =  None
		fd = int(file_descriptor["fd"])
		file_path = file_descriptor["path"]["value"]

		if syscall == "write" or syscall == "pwrite64":
			event = DiskWriteEvent(timestamp, host, pid, file_path, fd, offset, size, r_value, buffer, saveAsText)
		elif syscall == "read" or syscall == "pread64":
			event = DiskReadEvent(timestamp, host, pid, file_path, fd, offset, size, r_value, buffer, saveAsText)

		return event

def _discard_event(whitelist, event):
	if (event is None): return True

	if (EventType.is_disk(event._type)):
		in_white_list = False
		for folder in whitelist:
			if event._filename.startswith(folder):
				in_white_list = True
		if (in_white_list == False and len(whitelist) > 0): return True

	if (isinstance(event, SocketReceive) and event._sport in [9092, 53]) or (isinstance(event, SocketSend) and event._dport in [9092, 53]):
		return True

	if (isinstance(event, SocketConnect) and event._dport in [9092, 53]):
		return True

	return False

def _increment_call_handled_events_stats(events_traced, syscall, lock):
	lock.acquire()
	if syscall in events_traced:
		stats = events_traced[syscall]
		if "calls" in events_traced[syscall]:
			stats["calls"] += 1
		else:
			stats["calls"] = 1
		events_traced[syscall] = stats
	else:
		events_traced[syscall] = {"calls": 1, "saved": 0, "errors": 0, "discarded": 0}
	lock.release()

def _increment_saved_handled_events_stats(events_traced, syscall, lock):
	lock.acquire()
	if syscall in events_traced:
		stats = events_traced[syscall]
		if "saved" in events_traced[syscall]:
			stats["saved"] += 1
		else:
			stats["saved"] = 1
		events_traced[syscall] = stats
	else:
		events_traced[syscall] = {"calls": 0, "saved": 1, "errors": 0, "discarded": 0}
	lock.release()

def _increment_error_handled_events_stats(events_traced, syscall, lock):
	lock.acquire()
	if syscall in events_traced:
		stats = events_traced[syscall]
		if "errors" in events_traced[syscall]:
			stats["errors"] += 1
		else:
			stats["errors"] = 1
		events_traced[syscall] = stats
	else:
		events_traced[syscall] = {"calls": 0, "saved": 0, "errors": 1, "discarded": 0}
	lock.release()

def _increment_discarded_handled_events_stats(events_traced, syscall, lock):
	lock.acquire()
	if syscall in events_traced:
		stats = events_traced[syscall]
		if "discarded" in events_traced[syscall]:
			stats["discarded"] += 1
		else:
			stats["discarded"] = 1
		events_traced[syscall] = stats
	else:
		events_traced[syscall] = {"calls": 0, "saved": 0, "errors": 0, "discarded": 1}
	lock.release()

def _increment_saved_events_stats(events_saved, event, lock):
	lock.acquire()
	if event in events_saved:
		event_stats = events_saved[event]
	else:
		event_stats = { "saved" : 0, "truncated" : 0 }
	event_stats["saved"] += 1
	events_saved[event] = event_stats
	lock.release()

def _increment_truncated_events_stats(events_saved, event, lock):
	lock.acquire()
	if event in events_saved:
		event_stats = events_saved[event]
	else:
		event_stats = { "saved" : 0, "truncated" : 0 }
	event_stats["truncated"] += 1
	events_saved[event] = event_stats
	lock.release()

######################################################

def run_program_cmd(filename, capture_size, cmd):
	pid = os.fork()
	if pid == 0:
		paused = [True]
		def received(signum, frame):
			paused[0] = False

		signal.signal(signal.SIGCONT, received)
		while paused[0]:
			signal.pause()

		program = ["strace", "-o", filename, "-e", "trace=open,openat,read,pread64,write,pwrite64,accept,accept4,connect,socket,recv,recvfrom,recvmsg,send,sendto,sendmsg",\
						"-s", str(capture_size), "-tt", "-yy", "-f"]
		program.extend(cmd)
		logging.info("Started program ["  + " ".join(cmd) + "]")

		try:
			os.execvp("strace", program)
		except Exception as e:
			logging.error("Could not execute program: {}".format(e))
			os._exit(1)
	else:
		return pid

def run_program_pid(filename, capture_size, program_pid):
	pid = os.fork()
	if pid == 0:
		paused = [True]
		def received(signum, frame):
			paused[0] = False

		signal.signal(signal.SIGCONT, received)
		while paused[0]:
			signal.pause()

		program = ["strace", "-o", filename, "-e", "trace=open,openat,read,pread64,write,pwrite64,accept,accept4,connect,socket,recv,recvfrom,recvmsg,send,sendto,sendmsg",\
						"-s", str(capture_size), "-tt", "-yy", "-f", "-p", str(program_pid)]

		logging.info("Started program ["  + " ".join(program_pid) + "]")

		try:
			os.execvp("strace", program)
		except Exception as e:
			logging.error("Could not execute program: {}".format(e))
			os._exit(1)
	else:
		return pid

######################################################

def main():

	"""Main entry point for the script."""

	parser = argparse.ArgumentParser(prog='catstrace', description='This program is the strace-based tracer for the CAT pipeline tool.')

	parser.add_argument('--input', default=None,
						help="input filename")
	parser.add_argument('--pid', default=None,
						help="pid")
	parser.add_argument('--host', default=socket.getfqdn(),
						help="Hostname of traced machine")
	parser.add_argument('--hostip', default=socket.gethostbyname(socket.getfqdn()),
						help="Hostname of traced machine")
	parser.add_argument('--whitelist', default=None,
						help="white list file")
	parser.add_argument('--stats',action='store_true',
						help="print events stats")
	parser.add_argument('--text',action='store_true',
                        help="save data as text. Default saves only signatures.")
	parser.add_argument('--trace_output', default=None,
						help="output file")
	parser.add_argument('--esize', type=int, default=2561024,
						help="esize")

	args, cmd = parser.parse_known_args()

	CatStrace(args.input, args.host, args.hostip, cmd, args.pid, args.esize, whitelist=args.whitelist, stats=args.stats, saveAsText=args.text, output=args.trace_output).run()


if __name__ == '__main__':
	main()

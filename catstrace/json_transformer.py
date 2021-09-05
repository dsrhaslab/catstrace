from typing import Any
import codecs

from lark import Transformer, Tree


def convert(cls):
    def f(self, children):
        return cls(children[0])

    return f


def first_child():
    def f(self, children):
        return children[0]

    return f


class JsonTransformer(Transformer):
    def start(self, children):
        return children

    def line(self, children):
        pid, timestamp, body = children
        body["pid"] = pid
        body["timestamp"] = timestamp
        return body

    def syscall(self, children):
        name, args, result = children
        return {
            "type": "syscall",
            "name": name,
            "args": args,
            "result": result,
        }

    def resumed_syscall(self, children):
        name, args, result = children
        return {
            "type": "resumed_syscall",
            "name": name,
            "args": args,
            "result": result,
        }

    def unfinished_syscall(self, children):
        name, args = children
        return {
            "type": "unfinished_syscall",
            "name": name,
            "args": args,
        }

    def args(self, children):
        return children

    def string(self, children):
        return {
            "type": "string",
            "value": str(children[0][1:-1]),
        }

    def timestamp(self, children):
        hrs, mins, secs, usecs = children
        ts = ((int(str(hrs))*60 + int(str(mins)))*60 + int(str(secs)))*1000000 + int(str(usecs))
        return ts

    def number(self, children):
        return {
            "type": "number",
            "value": int(children[0]),
        }

    def r_error(self, children):
        r_error_code, r_error_message = children
        return {
            "type": "r_error",
            "value": r_error_code,
            "message": str(r_error_message)
        }

    def address(self, children):
        return {
            "type": "address",
            "value": str(children[0])
        }

    def file_descriptor(self, children):
        fd, path = children
        return {
            "type": "file_descriptor",
            "fd": fd,
            "path": path
        }

    def socket_path(self, children):
        socket_type, src, src_port, dst, dst_port = children
        return {
            "type": "socket_path",
            "socket_type": str(socket_type),
            "src": str(src),
            "src_port": int(src_port),
            "dst": str(dst),
            "dst_port": int(dst_port)
        }

    def local_socket_path(self, children):
        socket_type, src, src_port = children
        return {
            "type": "local_socket_path",
            "socket_type": str(socket_type),
            "src": str(src),
            "src_port": int(src_port),
        }

    def socket_ino_path(self, children):
        socket_type, ino_number = children
        return {
            "type": "socket_ino_path",
            "socket_type": str(socket_type),
            "ino_number": int(ino_number)
        }

    def file_path(self, children):
        return {
            "type": "file_path",
            "value": str(children[0]),
        }

    def other(self, children):
        return {
            "type": "other",
            "value": str(children[0]),
        }

    def braced(self, children):
        return {
            "type": "braced",
            "value": children[0],
        }

    def bracketed(self, children):
        return {
            "type": "bracketed",
            "value": children[0],
        }

    def key_value(self, children):
        key, value = children
        return {
            "type": "key_value",
            "key": str(key),
            "value": value,
        }

    def alert_body(self, children):
        return {
            "type": "alert",
            "message": str(children[0]),
        }

    def stop_body(self, children):
        return {
            "type": "stop",
            "message": str(children[0]),
        }

    def function_like(self, children):
        name, args = children
        return {
            "type": "function",
            "name": str(name),
            "args": args,
        }

    def sigset(self, children):
        return {
            "type": "sigset",
            "negated": children[0].type == "NEGATED",
            "args": [str(c) for c in children[1:]],
        }

    fd = convert(int)

    key = convert(str)

    body = first_child()

    name = convert(str)

    result = convert(str)

    signal = convert(str)

    pid = convert(int)

    value = first_child()

    message = convert(str)

    syscall_result = convert(dict)

    r_value = convert(int)

    r_unknown = convert(str)

def to_json(tree: Tree) -> Any:
    return JsonTransformer().transform(tree)[0]

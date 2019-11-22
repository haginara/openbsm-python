
import pwd
import grp
import logging
import struct
from datetime import datetime
from typing import List, Dict, Optional, Any, Type, TypeVar


from .audit_event import get_audit_events
from .bsm_h import *
from .bsm_errors import BSM_ERRORS
from .audit_record import *

from .lib.libproc import proc_pidpath

logger = logging.getLogger(__name__)

Token = TypeVar("Token", bound="BaseToken")
Rec = TypeVar("Record", bound="Record")

AUDIT_EVENTS = get_audit_events()

class ArgType(object):
    __order__ = ">"
    struct_fmt = None

    def __init__(self, rec: Rec):
        self._rec = rec
        self._raw = struct.unpack(self.fmt, rec.read(self.size))

        self._unpack()
    
    def __str__(self):
        return self.__repr__()
    
    @property
    def struct_fmt(self):
        raise NotImplementedError

    @property
    def fmt(self):
        return f"{self.__order__}{self.struct_fmt}"
    
    @property
    def size(self):
        return struct.calcsize(self.struct_fmt)
    
    @classmethod
    def unpack(cls, data):
        """ Unpack from data

        Example:
        arg = Argument.unpack(data[:Process.size])
        """
        obj = cls(data)
        obj._unpack()
        return obj
    
    def _unpack(self):
        return

class LEArgType(ArgType):
    __order__ = "<"

class BEArgType(ArgType):
    __order__ = ">"

class UInt64(ArgType):
    struct_fmt = "Q"

    def __repr__(self):
        return str(self.value)
    
    def _unpack(self):
        self.value = self._raw[0]
class UInt32(ArgType):
    struct_fmt = "I"

    def __repr__(self):
        return str(self.value)
    
    def _unpack(self):
        self.value = self._raw[0]

class UInt16(ArgType):
    struct_fmt = "H"

    def __repr__(self):
        return str(self.value)
    
    def _unpack(self):
        self.value = self._raw[0]

class UInt8(ArgType):
    struct_fmt = "B"

    def __repr__(self):
        return str(self.value)
    
    def _unpack(self):
        self.value = self._raw[0]
class EventType(ArgType):
    """
    EventType(rec)
    """
    struct_fmt = "H"

    def __repr__(self):
        return self.value.entry

    def _unpack(self):
        self.value = AUDIT_EVENTS.get(self._raw[0], "Unknown")

class DateTime(ArgType):
    struct_fmt = "I"

    def __repr__(self):
        return self.value.strftime("%c")
    
    def _unpack(self):
        self.value = datetime.fromtimestamp(self._raw[0])


class MSec(ArgType):
    struct_fmt = "I"
    
    def __repr__(self):
        return f" + {self.value} msec"
    
    def _unpack(self):
        self.value = self._raw[0]


class ReturnString(ArgType):
    struct_fmt = "B"
    
    def __repr__(self):
        return self.value
    def _unpack(self):
        if self._raw[0]:
            self.value = (
                    f"failure: Unknown error: {self._raw[0]}"
                    if self._raw[0] not in BSM_ERRORS
                    else f"failure : {BSM_ERRORS.get(self._raw[0])}"
                )
        else:
            self.value = "success"

class CompleteString(ArgType):
    struct_fmt = "B"

    def _unpack(self):
        self.value = "complete" if self._raw[0] == 0 else "failed"

    def __repr__(self):
        return self.value


class String(ArgType):
    struct_fmt = "H"

    def _unpack(self):
        length_fmt = f"{self._raw[0]}s"
        self._raw_string = struct.unpack(length_fmt, self._rec.read(struct.calcsize(length_fmt)))[0]
        self.value = self._raw_string
    
    def __repr__(self):
        return self.value.decode("utf-8")


class ByteString(String):
    struct_fmt = "H"

    def __repr__(self):
        return "0x" + "".join([f"{x:02x}" for x in self._raw_string])


class User(ArgType):
    struct_fmt = "I"

    def _unpack(self):
        try:
            self.value = pwd.getpwuid(self._raw[0]).pw_name
        except:
            self.value = "-1"

    def __repr__(self):
        return self.value


class Group(ArgType):
    struct_fmt = "I"

    def _unpack(self):
        try:
            self.value = grp.getgrgid(self._raw[0]).gr_name
        except:
            logger.debug(f"Fail to find group name: gid: {self._raw[0]}")
            self.value = self._raw[0]
    def __repr__(self):
        return str(self.value)

class Groups(ArgType):
    struct_fmt = "I"

    def __repr__(self):
        return self._raw

class IPv4Address(ArgType):
    struct_fmt = "I"

    def __repr__(self):
        return self.value

    def _unpack(self):
        self.value = (
            f"{int(self._raw[0] / pow(2, 24)) % 256}."
            f"{int(self._raw[0] / pow(2, 16)) % 256}."
            f"{int(self._raw[0] / pow(2, 8)) % 256}."
            f"{int(self._raw[0]) % 256}"
        )

class IPv6Address(ArgType):
    struct_fmt = "QQ"

    def __repr__(self):
        return self.value
    
    def _unpack(self):
        self.value = ":".join(self._raw)


class IPAddress(ArgType):
    """
    - IPv4
    - IPv6
    """
    struct_fmt = "I"

    def _unpack(self):
        self.addr_type = self._raw[0]
        if self.addr_type == 16:
            self.value = IPv6Address(self._rec)
        else:
            self.value = IPv4Address(self._rec)


class Process(ArgType):
    struct_fmt = "I"

    def _unpack(self):
        self.value = self._raw[0]
        self.name = proc_pidpath(self.value)

    def __repr__(self):
        return self.name or str(self.value)

class Uuid(ArgType):
    struc_fmt = ""

class Struct(ArgType):
    def __init__(self, data):
        self.add_argument("size", "I", argtype=int)
        self.add_argument("version", "B", argtype=int)
        self.add_argument("event_type", "H", argtype=EventType)
        self.add_argument("modifier", "H", argtype=int)
    
    def fetch(self, record):
        for name, fmt, argtype, kwargs in self.args:
            if "len_fmt" in kwargs:
                read = struct.calcsize(kwargs["len_fmt"])
                length = unpack_one(kwargs["len_fmt"], record.read(read))
                fmt = fmt.format(length=length)
                logger.debug(
                    f"len_fmt: {kwargs['len_fmt']}, len_fmt_size: {read}, length: {length}"
                )
            logger.debug(f"key: {name}, Format: {fmt}, argtype: {argtype}")
            size = struct.calcsize(fmt)
            r_value = unpack_one(fmt, record.read(size))
            value = argtype(r_value)
            logger.debug(f"r_value: {r_value}, type: {type(value)}, value: {value}")
            #setattr(self, f"_{name}", r_value)
            setattr(self, name, value)
import os
import abc
import struct
import logging
import time
import re
from collections import OrderedDict, namedtuple
from datetime import datetime
from typing import List, Dict, Optional, Any

from audit_event import AUDIT_EVENT, AuditEvents
from bsm_h import *
from audit_record import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AUDIT_EVENTS = AuditEvents().get_audit_events()

AUDIT_HEADER_SIZE = 18
AUDIT_TRAILER_SIZE = 7


class NotYetImplementedToken(Exception):
    pass


class UnknownHeader(Exception):
    pass


class BSM_TOKENS(abc.ABCMeta):
    __tokens__ = {}

    def __new__(metaclass, name, base, namespace):
        cls = abc.ABCMeta.__new__(metaclass, name, base, namespace)
        if getattr(cls, "token_id", None):
            print(cls.token_id)
            metaclass.__tokens__[cls.name] = cls()
        return cls

    def __get__(self, name):
        return self.__tokens__[name]


class BaseToken(metaclass=BSM_TOKENS):
    __delm__ = ","
    __order__ = ">"

    def __init__(self):
        self._args = {}
        self.id = id

        self._setup()

    @abc.abstractmethod
    def _setup(self):
        raise NotImplemented

    def get_length(self):
        return sum([struct.calcsize(self._args[key]) for key in self._args])

    def add_argument(self, name, arg_fmt, arg_type):
        self._args[name] = f"{self.__order__}{arg_fmt}"

    @classmethod
    def fetch(cls, record):
        obj = cls(record.header)
        current = 0
        for key in obj._args:
            fmt = obj._args[key]
            found = re.findall(r"{(.*)}", fmt)
            if found:
                fmt = fmt.format(**{key: getattr(obj, key) for key in found})
                obj._args[key] = fmt
            size = struct.calcsize(fmt)
            value = struct.unpack(fmt, record.get_data(size))[0]
            logger.debug(f"key: {key}, Format: {obj._args[key]}, value: {value}")
            setattr(obj, key, value)
            current += size

        return obj

    def __str__(self):
        return f"{self.delm}".join([f"{getattr(self, name)}" for name in self._args])

    def print(self, oflags: int):
        self.print_tok_type(self.id, self.token_name, oflags)
        self._print(oflags)

    def print_tok_type(self, tok_type, tokname, oflags):
        if oflags & AU_OFLAG_RAW:
            print(f"{tok_type}", end=self.delm)
        else:
            print(f"{tokname}", end=self.delm)

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self._args:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.delm}".join(
                    [
                        f"{getattr(self, name)}"
                        for name in self._args
                        if "size" not in name
                    ]
                )
            )
        else:
            print(
                f"{self.delm}".join(
                    [
                        f"{getattr(self, name)}"
                        for name in self._args
                        if "size" not in name
                    ]
                )
            )


class Header(BaseToken):
    token_name = "header"

    @property
    def event_type(self):
        return AUDIT_EVENTS.get(self._event_type, "Unknown")

    @event_type.setter
    def event_type(self, event_type):
        self._event_type = event_type


class EventType:
    pass


class DateTime:
    pass


class Header32(Header):
    """
        record byte count       4 bytes
        version #               1 byte    [2]
        event type              2 bytes
        event modifier          2 bytes
        seconds of time         4 bytes/8 bytes (32-bit/64-bit value)
        milliseconds of time    4 bytes/8 bytes (32-bit/64-bit value)
    Example:
        record = Record()
        record.generate(AUT_HEADER32)
    """

    token_id = AUT_HEADER32
    identifier = "header"

    def _setup(self):
        self.add_argument("size", "I", type=int)
        self.add_argument("version", "B", type=int)
        self.add_argument("event_type", "H", type=EventType)
        self.add_argument("modifier", "H", type=int)
        self.add_argument("time", "I", type=DateTime)
        self.add_argument("msec", "I", type=DateTime)


class Header32Ex(Header):
    """
    * The Solaris specifications for AUE_HEADER32_EX seem to differ a bit
    * depending on the bit of the specifications found.  The OpenSolaris source
    * code uses a 4-byte address length, followed by some number of bytes of
    * address data.  This contrasts with the Solaris audit.log.5 man page, which
    * specifies a 1-byte length field.  We use the Solaris 10 definition so that
    * we can parse audit trails from that system.
    *
    * record byte count       4 bytes
    * version #               1 byte     [2]
    * event type              2 bytes
    * event modifier          2 bytes
    * address type/length     4 bytes
    *   [ Solaris man page: address type/length     1 byte]
    * machine address         4 bytes/16 bytes (IPv4/IPv6 address)
    * seconds of time         4 bytes/8 bytes  (32/64-bits)
    * nanoseconds of time     4 bytes/8 bytes  (32/64-bits)
    """

    name = "Header32Ex"

    def _setup(self):
        self._args = {
            "size": ">I",
            "version": ">B",
            "event_type": ">H",
            "modifier": ">H",
            "ad_type": ">I",
            "address": ">I",
            "time": ">I",
            "msec": ">I",
        }


class Header64(Header):
    """
    record byte count       4 bytes
    event type              2 bytes
    event modifier          2 bytes
    seconds of time         4 bytes/8 bytes (32-bit/64-bit value)
    milliseconds of time    4 bytes/8 bytes (32-bit/64-bit value)
    version #
    """

    name = "Header64"

    def _setup(self):
        self._args = {
            "size": ">I",
            "version": ">B",
            "event_type": ">H",
            "modifier": ">H",
            "time": ">I",
            "msec": ">I",
        }


class Trailer(BaseToken):
    """
    trailer magic                        2 bytes
    record size                          4 bytes
    """

    name = "Trailer"
    token_name = "trailer"

    def _setup(self):
        self._args = {"magic": ">H", "count": ">I"}

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self._args:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(f"{self.count}")
        else:
            print(f"{self.count}")


class Subject32(BaseToken):
    """
    audit ID                4 bytes
    effective user ID       4 bytes
    effective group ID      4 bytes
    real user ID            4 bytes
    real group ID           4 bytes
    process ID              4 bytes
    session ID              4 bytes
    terminal ID
        port ID               4 bytes/8 bytes (32-bit/64-bit value)
        machine address       4 bytes
    """

    name = "Subject32"
    token_name = "subject32"

    def _setup(self):
        self._args = {
            "auid": ">I",
            "euid": ">I",
            "egid": ">I",
            "ruid": ">I",
            "rgid": ">I",
            "pid": ">I",
            "sid": ">I",
            "tid_port": ">I",
            "tid_address": ">I",
        }

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self._args:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.auid}{self.delm}"
                f"{self.euid}{self.delm}"
                f"{self.egid}{self.delm}"
                f"{self.ruid}{self.delm}"
                f"{self.rgid}{self.delm}"
                f"{self.pid}{self.delm}"
                f"{self.sid}{self.delm}"
                f"{self.tid_port}{self.delm}"
                f"{self.tid_address}"
            )
        else:
            print(
                f"{self.auid}{self.delm}"
                f"{self.euid}{self.delm}"
                f"{self.egid}{self.delm}"
                f"{self.ruid}{self.delm}"
                f"{self.rgid}{self.delm}"
                f"{self.pid}{self.delm}"
                f"{self.sid}{self.delm}"
                f"{self.tid_port}{self.delm}"
                f"{self.tid_address}"
            )


AUT_SUBJECT32_EX


class Argument(BaseToken):
    """
    /*
    * argument #              1 byte
    * argument value          4 bytes/8 bytes (32-bit/64-bit value)
    * text length             2 bytes
    * text                    N bytes + 1 terminating NULL byte
    */
    """

    token_name = "argument"

    def _setup(self):
        self._args = {
            "no": ">b",
            "val": ">I",
            "text_size": ">H",
            "text": ">{text_size}s",
        }


class Arg32(Argument):
    name = "Arg32"


class Arg64(Argument):
    name = "Arg64"

    def _setup(self):
        self._args = {
            "no": ">b",
            "val": ">Q",
            "text_size": ">H",
            "text": ">{text_size}s",
        }


class Acl(BaseToken):
    name = "Acl"
    token_name = "acl"


class Uuid(BaseToken):
    """
    """


class Text(BaseToken):
    name = "Text"
    token_name = "text"

    def _setup(self):
        self._args = {"size": ">H", "data": ">{size}s"}

    @property
    def data(self):
        return self._data.decode()

    @data.setter
    def data(self, data):
        self._data = data

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self._args:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(f"{self.size}{self.delm}" f"{self.data}")
        else:
            print(f"{self.size}{self.delm}" f"{self.data}")


class Path(Text):
    name = "Path"
    token_name = "path"


class Return32(BaseToken):
    name = "Return32"
    token_name = "return"

    def _setup(self):
        self._args = {"errno": ">B", "value": ">I"}

    @property
    def errno(self):
        if self._errno == 0:
            return "success"
        else:
            return "failure"

    @errno.setter
    def errno(self, errno):
        self._errno = errno

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self._args:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(f"{self.errno}{self.delm}" f"{self.value}")
        else:
            print(f"{self.errno}{self.delm}" f"{self.value}")


class Identity(BaseToken):
    """
    <identity signer-type="1" signing-id="com.apple.xpc.launchd" signing-id-truncated="no" team-id="" team-id-truncated="no" cdhash="0x2623e0657eb3c1c063dec9aeef40a0ce175d1ec9" />
    """

    name = "Identity"
    token_name = "identity"

    def _setup(self):
        self._args = {
            "signer_type": ">I",
            "signing_size": ">H",
            "signing_id": ">{signing_size}s",
            "signing_id_truncated": ">B",
            "team_id_length": ">H",
            "team_id": ">{team_id_length}s",
            "team_id_truncated": ">B",
            "cdhash_size": ">H",
            "cdhash": ">{cdhash_size}s",
        }

    @property
    def signing_id(self):
        return self._signing_id.decode()

    @signing_id.setter
    def signing_id(self, signing_id):
        self._signing_id = signing_id

    @property
    def team_id(self):
        return self._team_id

    @team_id.setter
    def team_id(self, team_id):
        self._team_id = team_id

    @property
    def cdhash(self):
        return "0x" + "".join([f"{x:2x}" for x in self._cdhash])

    @cdhash.setter
    def cdhash(self, cdhash):
        self._cdhash = cdhash

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self._args:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.signer_type}{self.delm}"
                f"{self.signing_id}{self.delm}"
                f"{self.signing_id_truncated}{self.delm}"
                f"{self.team_id_truncated}{self.delm}"
                f"{self.cdhash}"
            )
        else:
            print(
                f"{self.signer_type}{self.delm}"
                f"{self.signing_id}{self.delm}"
                f"{self.signing_id_truncated}{self.delm}"
                f"{self.team_id_truncated}{self.delm}"
                f"{self.cdhash}"
            )

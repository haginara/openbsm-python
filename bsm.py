import os
import struct
import logging
import time
import re
from collections import OrderedDict, namedtuple
from datetime import datetime
from typing import List, Dict, Optional, Any

from audit_event import AUDIT_EVENT, get_audit_events
from bsm_h import *
from audit_record import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AUDIT_EVENTS = get_audit_events()

AUDIT_HEADER_SIZE = 18
AUDIT_TRAILER_SIZE = 7


class NotYetImplementedToken(Exception):
    pass


class UnknownHeader(Exception):
    pass


class Record:
    def __init__(self, header, data, length):
        self.header = header
        self.data = data
        self.length = length
        self.bytesread = 0
    
    def remains(self):
        return self.length - self.bytesread

    def get_data(self, size):
        start = self.bytesread
        end = start + size
        if end > self.length:
            raise Exception(f"size is bigger than length: {end} > {self.length}")
        self.bytesread += size
        logger.debug(f"start: {start}, end: {end}")
        return self.data[start: end]


class BaseToken(object):
    delm = ","

    def __init__(self, id: int):
        self.id = id

        self._setup()
    
    def _setup(self):
        raise NotImplementedError

    def get_length(self):
        return sum([struct.calcsize(self.format_dict[key]) for key in self.format_dict])

    @classmethod
    def fetch(cls, record: Record):
        obj = cls(record.header)
        current = 0
        for key in obj.format_dict:
            fmt = obj.format_dict[key]
            found = re.findall(r'{(.*)}', fmt)
            if found:
                fmt = fmt.format(**{key: getattr(obj, key) for key in found})
                obj.format_dict[key] = fmt
            size = struct.calcsize(fmt)
            value = struct.unpack(fmt, record.get_data(size))[0]
            logger.debug(f"key: {key}, Format: {obj.format_dict[key]}, value: {value}")
            setattr(obj, key, value)
            current += size
        
        return obj

    def __str__(self):
        return f"{self.delm}".join([f"{getattr(self, name)}" for name in self.format_dict])

    def print(self, oflags: int):
        self.print_tok_type(self.id, self.token_name, oflags)
        self._print(oflags)
    
    def print_tok_type(self, tok_type, tokname, oflags):
        if oflags & AU_OFLAG_RAW:
            print(f"{tok_type}", end=self.delm)
        else:
            print(f"{tokname}", end=self.delm)

class RootToken(BaseToken):
    token_name = "header"
    name = "Root"

    def _setup(self):
        self.format_dict = {
            "header": ">B",
            "recsize": ">I",
            "data": ">s{recsize}",
        }

class Header(BaseToken):
    token_name = "header"

    @property
    def event_type(self):
        return AUDIT_EVENTS.get(self._event_type, "Unknown")
    
    @event_type.setter
    def event_type(self, event_type):
        self._event_type = event_type

class Header32(Header):
    """
        record byte count       4 bytes
        version #               1 byte    [2]
        event type              2 bytes
        event modifier          2 bytes
        seconds of time         4 bytes/8 bytes (32-bit/64-bit value)
        milliseconds of time    4 bytes/8 bytes (32-bit/64-bit value)
    """
    name = "Header32"

    def _setup(self):
        self.format_dict = {
            "size": ">I",
            "version": ">B",
            "event_type": ">H",
            "modifier": ">H",
            "time": ">I",
            "msec": ">I",
        }

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self.format_dict:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.size}{self.delm}"
                f"{self.version}{self.delm}"
                f"{self._event_type}{self.delm}"
                f"{self.modifier}{self.delm}"
                f"{self.time}{self.delm}"
                f"{self.msec}"
            )
        else:
            print(
                f"{self.size}{self.delm}"
                f"{self.version}{self.delm}"
                f"{self.event_type.entry}{self.delm}"
                f"{self.modifier}{self.delm}"
                f"{datetime.fromtimestamp(self.time).isoformat()}{self.delm}"
                f"+ {self.msec} msec"
            )



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
        self.format_dict = {
            "size": ">I",
            "version": ">B",
            "event_type": ">H",
            "modifier": ">H",
            "ad_type": ">I",
            "address": ">I",
            "time":">I",
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
        self.format_dict = {
            "size": ">I",
            "version": ">B",
            "event_type": ">H",
            "modifier": ">H",
            "time":">I",
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
        self.format_dict = {
            "magic": ">H",
            "count": ">I",
        }
    
    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self.format_dict:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.count}"
            )
        else:
            print(
                f"{self.count}"
            )


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
        self.format_dict = {
            "no": ">b",
            "val": ">I",
            "len": ">H",
            "text": ">s",
        }

class Arg32(Argument):
    name = "Arg32"

class Arg64(Argument):
    name = "Arg64"


class Uuid(BaseToken):
    """
    """

class Text(BaseToken):
    name = "Text"
    token_name = "text"

    def _setup(self):
        self.format_dict = {
            "size": ">H",
            "data": ">{size}s",
        }

    @property
    def data(self):
        return self._data.decode()
    
    @data.setter
    def data(self, data):
        self._data = data

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name in self.format_dict:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.size}{self.delm}"
                f"{self.data}"
            )
        else:
            print(
                f"{self.size}{self.delm}"
                f"{self.data}"
            )

class Path(Text):
    name = "Path"
    token_name = "path"

class Return32(BaseToken):
    name = "Return32"
    token_name = "return"

    def _setup(self):
        self.format_dict = {
            "errno": ">B",
            "value": ">I",
        }
    
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
            for name in self.format_dict:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.errno}{self.delm}"
                f"{self.value}"
            )
        else:
            print(
                f"{self.errno}{self.delm}"
                f"{self.value}"
            )

class Identity(BaseToken):
    """
    <identity signer-type="1" signing-id="com.apple.xpc.launchd" signing-id-truncated="no" team-id="" team-id-truncated="no" cdhash="0x2623e0657eb3c1c063dec9aeef40a0ce175d1ec9" />
    """
    name = "Identity"
    token_name = "identity"

    def _setup(self):
        self.format_dict = {
            "signer_type": ">I",
            "signing_size": ">H",
            "signing_id": ">{signing_size}s",
            "signing_id_truncated": ">B",
            "team_id_length": ">H",
            "team_id": ">{team_id_length}s",
            "team_id_truncated": ">B",
            "cdhash_size": ">H",
            "cdhash": ">{cdhash_size}s"
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
            for name in self.format_dict:
                print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.signer_type}{self.delm}"
                f"{self.signing_id}{self.delm}"
                f"{self.signing_id_truncated}{self.delm}"
                f"{self.team_id_truncated}{self.delm}"
                f"{self.cdhash}{self.delm}"
            )
        else:
            print(
                f"{self.signer_type}{self.delm}"
                f"{self.signing_id}{self.delm}"
                f"{self.signing_id_truncated}{self.delm}"
                f"{self.team_id_truncated}{self.delm}"
                f"{self.cdhash}{self.delm}"
            )


def au_print_flag_tok(token, delm: str, oflags: int):
    if token.id == AUT_HEADER32:
        token.print(oflags)

def au_fetch_invalid_tok(record: Record):
    err = 0
    recoversize = record.length - (record.bytesread + AUDIT_TRAILER_SIZE)
    if recoversize <= 0:
        return -1

    invalid_length = recoversize
    #SET_PTR((char*)buf, len, tok->tt.invalid.data, recoversize, tok->len,
    return 0

BSM_TOKEN_FETCHS = {
    AUT_HEADER32: Header32,
    AUT_TEXT: Text,
    AUT_PATH: Path,
    AUT_RETURN32: Return32,
    AUT_IDENTITY: Identity,
    AUT_TRAILER: Trailer,
}
def au_fetch_tok(record: Record):
    while record.bytesread < record.length:
        _bsm_type = record.get_data(1)
        record.header = struct.unpack('>B', _bsm_type)[0]
        logger.debug(f"{record.header}")
        if record.header in BSM_TOKEN_FETCHS:
            yield BSM_TOKEN_FETCHS[record.header].fetch(record)
        else:
            raise NotYetImplementedToken(f"NotYeImplementedToken: 0x{record.header:x}, reamins: {record.remains()}")
        logger.info(f"Total: {record.length}, read: {record.bytesread}")



def au_read_rec(fp): 
    while True:
        try:
            _bsm_type = fp.read(1)
        except Exception as e:
            raise Exception(e)
        bsm_type = struct.unpack('b', _bsm_type)[0]
        #print(bsm_type)
        if bsm_type in [AUT_HEADER32, AUT_HEADER32_EX, AUT_HEADER64, AUT_HEADER64_EX]:
            _recsize = fp.read(4)
            #print(f"recsize: {recsize}")
            recsize = struct.unpack('>I', _recsize)[0]
            #print(f"recsize(unpacked): {recsize}")
            if recsize < struct.calcsize("I") + struct.calcsize("b"):
                return None
            data = fpread(recsize)
            #yield Record(bsm_type, _bsm_type + _recsize + data, recsize)

        elif bsm_type == AUT_OTHER_FILE32:
            pass
        else:
            #sec
            #msec
            #filenamelen

            #type
            #sec
            #msec
            #filenamelen
            #ntohs(filenamelen)
            #buffer = type | sec | msec | filenamelen | noths(filenamelen)
            raise UnknownHeader(f"Unknown header: {bsm_type}")

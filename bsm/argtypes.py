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

    def __init__(self, name=""):
        self.name = name

    def __call__(self, rec: Rec):
        self._rec = rec
        self._raw = struct.unpack(self.fmt, rec.read(self.size))

        self._unpack()

        return self

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
    def unpack(cls, rec: Rec):
        """ Unpack from record

        Example:
        arg = Argument.unpack(rec)
        """
        obj = cls()
        obj._rec = rec
        obj._raw = struct.unpack(obj.fmt, rec.read(obj.size))
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

    def __init__(self, length_fmt="H", until_null=False, with_null=False, max_length=None):
        self.struct_fmt = length_fmt
        self.until_null = until_null
        self.with_null = with_null
        self.max_length = max_length

    def _unpack(self):
        if self.until_null:
            self._raw_string = b""
            while True:
                c = self._rec.read(1)
                logger.info(f"String._unpack: {c}")
                if c == b'\0':
                    break
                self._raw_string += c
                if self.max_length and len(self._raw_string) >= self.max_length:
                    self._raw_string[-1] = b'\0'
                    break
        else:
            length = self._raw[0] + 1 if self.with_null else self._raw[0]
            if self.max_length and length > self.max_length:
                length = self.max_length
            length_fmt = f"{self.__order__}{length}s"
            self._raw_string = struct.unpack(
                length_fmt, self._rec.read(struct.calcsize(length_fmt))
            )[0]
        self.value = self._raw_string

    def __repr__(self):
        return self.value.decode("utf-8")


class Texts(ArgType):
    """
    fetch_execenv_tok(tokenstr_t *tok, u_char *buf, int len)
    {
        int err = 0;
        u_int32_t i;
        u_char *bptr;

        READ_TOKEN_U_INT32(buf, len, tok->tt.execenv.count, tok->len, err);
        if (err)
            return (-1);

        for (i = 0; i < tok->tt.execenv.count; i++) {
            bptr = buf + tok->len;
            if (i < AUDIT_MAX_ENV)
                tok->tt.execenv.text[i] = (char*)bptr;

            /* Look for a null terminated string. */
            while (bptr && (*bptr != '\0')) {
                if (++tok->len >= (u_int32_t)len)
                    return (-1);
                bptr = buf + tok->len;
            }
            if (!bptr)
                return (-1);
            tok->len++; /* \0 character */
        }
        if (tok->tt.execenv.count > AUDIT_MAX_ENV)
            tok->tt.execenv.count = AUDIT_MAX_ENV;

        return (0);
    }
    """

    struct_fmt = "I"

    def _unpack(self):
        self.value = []
        count = self._raw[0]
        text = b""
        for i in range(count):
            c = None
            while c != b"\0":
                c = self._rec.read(1)
                text.append(c)
            self.value.append(text)

    def __repr__(self):
        return ",".join([s.decode("utf-8") for s in self.value])


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
    """TODO: (int64,int64) to str
    """
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
            self.value = IPv6Address()(self._rec)
        else:
            self.value = IPv4Address()(self._rec)


class Process(ArgType):
    struct_fmt = "I"

    def _unpack(self):
        self.value = self._raw[0]
        self.name = proc_pidpath(self.value)

    def __repr__(self):
        return self.name or str(self.value)


class Uuid(ArgType):
    """ TODO: UUID or UUID_BE
    """

    struc_fmt = ""


from collections import OrderedDict
class Struct(object):
    """ TODO: Stuct is set of other Argtyps.

    """

    def __init__(self):
        self.values = OrderedDict()

    def __repr__(self):
        return f"{self.__class__}"

    def __getattr__(self, value):
        if value not in self.__dict__:
            return self.values[value]
        return self.__dict__[value]

    @property
    def token_id(self):
        raise NotImplemented

    @property
    def identifier(self):
        raise NotImplemented

    @property
    def __fields__(self):
        raise NotImplemented

    def fetch(self, rec: Rec):
        for name, field in self.__fields__:
            if name == "_":
                field.fetch(rec)
                self.values.update(field.values)
                continue
            elif isinstance(field, str):
                field = getattr(self, field)
            self.values[name] = field(rec)
        logger.info(f"fetch: {self.values}")

class BSMStruct(Struct):
    __delm__ = ","

    @staticmethod
    def get_token(token_id: int, rec: Rec):
        for subclass in BSMStruct.__subclasses__():
            if subclass.token_id == token_id:
                token = subclass()
                logger.info(f"Get_token: {token}, {token_id}")
                token.fetch(rec)
                return token
        raise NotImplementedError(token_id)

    def print(self, oflags: int):
        if oflags & AU_OFLAG_RAW:
            print(f"{self.token_id}", end=self.__delm__)
        else:
            print(f"{self.identifier}", end=self.__delm__)
        self._print(oflags)

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name  in self.values:
                print(f"{name}={self.values[name]}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.__delm__}".join(
                    [f"{self.values[name]}" for name in self.values]
                )
            )
        else:
            print(
                f"{self.__delm__}".join(
                    [f"{self.values[name]}" for name in self.values]
                )
            )
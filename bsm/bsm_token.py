import os
import abc
import struct
import logging
import time

from collections import OrderedDict, namedtuple
from datetime import datetime
from typing import List, Dict, Optional, Any, Type, TypeVar

from .audit_event import AUDIT_EVENT, get_audit_events
from .bsm_h import *
from .bsm_errors import BSM_ERRORS
from .audit_record import *
from .argtypes import *

logger = logging.getLogger(__name__)

#https://github.com/openbsm/openbsm/blob/master/libbsm/bsm_io.c

AUDIT_HEADER_SIZE = 18
AUDIT_TRAILER_SIZE = 7

Token = TypeVar("Token", bound="BaseToken")
Rec = TypeVar("Record", bound="Record")


class NotImplementedToken(Exception):
    pass


class UnknownHeader(Exception):
    pass


def unpack_one(fmt, data):
    one = struct.unpack(fmt, data)[0]
    logger.debug(f"data: {data}, unpacked: {one}")
    return one


class TokenFetcher(abc.ABCMeta):
    __tokens__ = {}

    def __new__(metaclass, name, base, namespace):
        cls = abc.ABCMeta.__new__(metaclass, name, base, namespace)
        if getattr(cls, "token_id", None):
            cls.token_name = f"AUT_{name.upper()}"
            logger.debug(cls.token_id, cls.token_name)
            metaclass.__tokens__[cls.token_id] = cls
        return cls

    @classmethod
    def get_token(cls, token_id: int) -> Token:
        obj = cls.__tokens__.get(token_id, None)
        if obj is None:
            raise NotImplementedError(f"{token_id}(0x{token_id:x})")
        return obj()

    @classmethod
    def fetch_token(cls, token_id: int, record: Rec) -> Optional[Token]:
        token = TokenFetcher.get_token(token_id)
        if token is None:
            return None
        for name, fmt, argtype, kwargs in token.args:
            if "len_fmt" in kwargs:
                read = struct.calcsize(kwargs["len_fmt"])
                length = unpack_one(kwargs["len_fmt"], record.get_data(read))
                fmt = fmt.format(length=length)
                logger.debug(
                    f"len_fmt: {kwargs['len_fmt']}, len_fmt_size: {read}, length: {length}"
                )
            logger.debug(f"key: {name}, Format: {fmt}, argtype: {argtype}")
            size = struct.calcsize(fmt)
            r_value = unpack_one(fmt, record.get_data(size))
            value = argtype(r_value)
            logger.debug(f"r_value: {r_value}, type: {type(value)}")
            logger.debug(f"value: {value}")
            setattr(token, f"_{name}", r_value)
            setattr(token, name, value)
        return token


class BaseToken(metaclass=TokenFetcher):
    __delm__ = ","
    __order__ = ">"

    def __init__(self):
        self.args = []
        self._setup()

    def __repr__(self):
        return f"{self.token_name}"

    # @abc.abstractproperty
    @abc.abstractmethod
    def _setup(self):
        raise NotImplemented

    def add_argument(self, name, argfmt, argtype, **kwargs):
        """
        kwargs:
         - size
        """
        if "len_fmt" in kwargs:
            kwargs["len_fmt"] = f"{self.__order__}{kwargs['len_fmt']}"
        self.args.append((name, f"{self.__order__}{argfmt}", argtype, kwargs))

    def get_length(self):
        return sum([struct.calcsize(self.args[key][0]) for key in self.args])

    def __str__(self):
        return f"{self.token_id}{self.__delm__}".join(
            [f"{getattr(self, arg[0])}" for arg in self.args]
        )

    def fetch(self, token_id: int, record: Rec) -> None:
        for name, fmt, argtype, kwargs in self.args:
            if "len_fmt" in kwargs:
                read = struct.calcsize(kwargs["len_fmt"])
                length = unpack_one(kwargs["len_fmt"], record.get_data(read))
                fmt = fmt.format(length=length)
                logger.debug(
                    f"len_fmt: {kwargs['len_fmt']}, len_fmt_size: {read}, length: {length}"
                )
            logger.debug(f"key: {name}, Format: {fmt}, argtype: {argtype}")
            size = struct.calcsize(fmt)
            r_value = unpack_one(fmt, record.get_data(size))
            value = argtype(r_value)
            logger.debug(f"r_value: {r_value}, type: {type(value)}")
            logger.debug(f"value: {value}")
            setattr(self, f"_{name}", r_value)
            setattr(self, name, value)

    def print_tok_type(self, tok_type, tokname, oflags):
        if oflags & AU_OFLAG_RAW:
            print(f"{tok_type}", end=self.__delm__)
        else:
            print(f"{tokname}", end=self.__delm__)
  
    def print(self, oflags: int):
        if oflags & AU_OFLAG_RAW:
            print(f"{self.token_id}", end=self.__delm__)
        else:
            print(f"{self.identifier}", end=self.__delm__)
        self._print(oflags)
    
    def asdict(self):
        return { name: f"{getattr(self, name)}" for name, _, _, kw in self.args if kw.get("show", True) }

    def _print(self, oflags: int):
        if oflags & AU_OFLAG_XML:
            for name, _, _, kw in self.args:
                if kw.get("show", True):
                    print(f"{name}={getattr(self, name)}")
        elif oflags & AU_OFLAG_RAW:
            print(
                f"{self.__delm__}".join(
                    [
                        f"{getattr(self, name)}"
                        for name, _, _, kw in self.args
                        if kw.get("show", True)
                    ]
                )
            )
        else:
            print(
                f"{self.__delm__}".join(
                    [
                        f"{getattr(self, name)}"
                        for name, _, _, kw in self.args
                        if kw.get("show", True)
                    ]
                )
            )


class Header(BaseToken):
    identifier = "header"

    def _setup(self):
        self.add_argument("size", "I", argtype=int)
        self.add_argument("version", "B", argtype=int)
        self.add_argument("event_type", "H", argtype=EventType)
        self.add_argument("modifier", "H", argtype=int)


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

    def _setup(self):
        super()._setup()
        self.add_argument("time", "I", argtype=DateTime)
        self.add_argument("msec", "I", argtype=MSec)


class Header32_Ex(Header):
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

    token_id = AUT_HEADER32_EX

    def _setup(self):
        super()._setup()
        self.add_argument("ad_type", "I", argtype=int)
        self.add_argument("address", "I", argtype=Ipv4Address)
        self.add_argument("time", "I", argtype=DateTime)
        self.add_argument("msec", "I", argtype=MSec)


class Trailer(BaseToken):
    """
    trailer magic                        2 bytes
    record size                          4 bytes
    """

    token_id = AUT_TRAILER
    identifier = "trailer"

    def _setup(self):
        self.add_argument("magic", "H", argtype=int, show=False)
        self.add_argument("count", "I", argtype=int)


class Argument(BaseToken):
    """
    * argument #              1 byte
    * argument value          4 bytes/8 bytes (32-bit/64-bit value)
    * text length             2 bytes
    * text                    N bytes + 1 terminating NULL byte
    """

    token_id = AUT_ARG
    identifier = "argument"

    def _setup(self):
        self.add_argument("no", "b", argtype=int)
        self.add_argument("val", "I", argtype=hex)
        self.add_argument("text", "{length}s", len_fmt="H", argtype=String)


class Arg32(Argument):
    token_id = AUT_ARG32


class Arg64(Argument):
    """
       "no": ">b",
        "val": ">Q",
        "text_size": ">H",
        "text": ">{text_size}s",
    """

    token_id = AUT_ARG64

    def _setup(self):
        self.add_argument("no", "b", argtype=int)
        self.add_argument("val", "Q", argtype=hex)
        self.add_argument("text", "{length}s", len_fmt="H", argtype=String)


class Text(BaseToken):
    token_id = AUT_TEXT
    identifier = "text"

    def _setup(self):
        self.add_argument("data", "{length}s", len_fmt="H", argtype=String)


class Path(Text):
    token_id = AUT_PATH
    identifier = "path"


class Return(BaseToken):
    identifier = "return"

    def _setup(self):
        self.add_argument("errno", "B", argtype=ReturnString)
       

class Return32(Return):
    """
        "errno": ">B",
        "value": ">I",
    """
    token_id = AUT_RETURN32
    
    def _setup(self):
        super()._setup()
        self.add_argument("value", "I", argtype=int)

class Return64(Return):
    token_id = AUT_RETURN64

    def _setup(self):
        super()._setup()
        self.add_argument("value", "Q", argtype=int)

class ReturnUuid(Return):
    token_id = AUT_RETURN_UUID
    identifier = "ret_uuid"
    def _setup(self):
        super()._setup()
        self.add_argument("uuid_be", "sizeof_uuid", argtype='uuid')
        self.add_argument("uuid", "{length}s", len_fmt="H", argtype=String)

class Identity(BaseToken):
    """
    "signer_type": ">I",
    "signing_size": ">H",
    "signing_id": ">{signing_size}s",
    "signing_id_truncated": ">B",
    "team_id_length": ">H",
    "team_id": ">{team_id_length}s",
    "team_id_truncated": ">B",
    "cdhash_size": ">H",
    "cdhash": ">{cdhash_size}s"
    """

    token_id = AUT_IDENTITY
    identifier = "identity"

    def _setup(self):
        self.add_argument("signer_type", "I", argtype=int)
        self.add_argument("signing_id", "{length}s", len_fmt="H", argtype=String)
        self.add_argument("signing_id_truncated", "B", argtype=CompleteString)
        self.add_argument("team_id", "{length}s", len_fmt="H", argtype=String)
        self.add_argument("team_id_truncated", "B", argtype=CompleteString)
        self.add_argument("cbhash", "{length}s", len_fmt="H", argtype=ByteString)


class Subject(BaseToken):
    token_id = AUT_SUBJECT
    identifier = "subject"

    def _setup(self):
        self.add_argument("auid", "I", argtype=User)
        self.add_argument("euid", "I", argtype=User)
        self.add_argument("egid", "I", argtype=Group)
        self.add_argument("ruid", "I", argtype=User)
        self.add_argument("rgid", "I", argtype=Group)
        self.add_argument("pid", "I", argtype=Process)
        self.add_argument("sid", "I", argtype=int)


class Subject32(Subject):
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

    token_id = AUT_SUBJECT32

    def _setup(self):
        super()._setup()
        self.add_argument("tid_port", "I", argtype=int)
        self.add_argument("tid_address", "I", argtype=Ipv4Address)


class Subject32_Ex(Subject):
    """
    * audit ID                     4 bytes
    * euid                         4 bytes
    * egid                         4 bytes
    * ruid                         4 bytes
    * rgid                         4 bytes
    * pid                          4 bytes
    * sessid                       4 bytes
    * terminal ID
    *   portid             4 bytes
    *	 type				4 bytes
    *   machine id         16 bytes
    """

    token_id = AUT_SUBJECT32_EX
    identifier = "subject_ex"

    def _setup(self):
        super()._setup()
        self.add_argument("tid_port", "I", argtype=int)
        self.add_argument("tid_type", "I", argtype=int, show=False)
        # Not Support ipv6 yet
        self.add_argument("tid_addr", "I", argtype=Ipv4Address)

#TODO: Complete Subject64
class Subject64(Subject):
    token_id = AUT_SUBJECT64

#TODO: Complete Subject64Ex
class Subject64Ex(Subject):
    token_id = AUT_SUBJECT64_EX

class Attr(BaseToken):
    """
    * file access mode        4 bytes
    * owner user ID           4 bytes
    * owner group ID          4 bytes
    * file system ID          4 bytes
    * node ID                 8 bytes
    * device                  4 bytes/8 bytes (32-bit/64-bit)
    """
    token_id = AUT_ATTR
    identifier = "attribute"

    def _setup(self):
        self.add_argument('mode', "I", argtype=int)
        self.add_argument('uid', "I", argtype=int)
        self.add_argument('gid', "I", argtype=int)
        self.add_argument('fsid', "I", argtype=int)
        self.add_argument('nodeid', "Q", argtype=int)
        self.add_argument('device', "I", argtype=int)

class Attr32(Attr):
    token_id = AUT_ATTR32

class Attr64(Attr):
    token_id = AUT_ATTR64


class Opaque(BaseToken):
    token_id = AUT_OPAQUE
    identifier = "opaque"

    def _setup(self):
        self.add_argument("data", "{length}s", len_fmt="H", argtype=ByteString)

class Uuid(BaseToken):
    toekn_id = AUT_ARG_UUID
    identifier = "uuid"

class Exit(BaseToken):
    """
    * status                  4 bytes
    * return value            4 bytes
    """
    token_id = AUT_EXIT
    identifier = "exit"

    def _setup(self):
        self.add_argument('errval', 'I', argtype=int)
        self.add_argument('retval', 'I', argtype=int)

class ExecArgs(BaseToken):
    """
     * count                   4 bytes
    * text                    count null-terminated string(s)
    fetch_execarg_tok(tokenstr_t *tok, u_char *buf, int len)
{
	int err = 0;
	u_int32_t i;
	u_char *bptr;

	READ_TOKEN_U_INT32(buf, len, tok->tt.execarg.count, tok->len, err);
	if (err)
		return (-1);

	for (i = 0; i < tok->tt.execarg.count; i++) {
		bptr = buf + tok->len;
		if (i < AUDIT_MAX_ARGS)
			tok->tt.execarg.text[i] = (char*)bptr;

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
	if (tok->tt.execarg.count > AUDIT_MAX_ARGS)
		tok->tt.execarg.count = AUDIT_MAX_ARGS;

	return (0);
}
    """
    token_id = AUT_EXEC_ARGS
    identifier = "exec arg"

    def _setup(self):
        self.add_argument("")

class ExecEnv(BaseToken):
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
    """
    token_id = AUT_EXEC_ENV
    identifier = "exec env"

class OtherFile(BaseToken):
    """
    * seconds of time          4 bytes
    * milliseconds of time     4 bytes
    * file name len            2 bytes
    * file pathname            N bytes + 1 terminating NULL byte
    """
    token_id = AUT_OTHER_FILE32
    identifier = "file"

    def _setup(self):
        self.add_argument("time", "I", argtype=int)
        self.add_argument("msec", "I", argtype=MSec)
        self.add_argument("pathname", "{length}s", len_fmt="H", argtype=String)


class Groups(ArgType):
    def __init__(self, groups):
        self._groups = groups

class NewGroups(BaseToken):
    """
     * number groups           2 bytes
    * group list              count * 4 bytes
    """
    token_id = AUT_NEWGROUPS
    identifier = "group"
    
    def _setup(self):
        self.add_argument("groups", "{count}I", argtype=Groups)

class InAddr(BaseToken):
    """
     * Internet addr 4 bytes
    """
    token_id = AUT_IN_ADDR
    identifier = "ip addr"

    def _setup(self):
        self.add_argument("addr", "I", argtype=Ipv4Address)

class InAddrEx(BaseToken):
    """
    type 4 bytes
    address 16 bytes
    """
    token_id = AUT_IN_ADDR_EX
    identifier = "ip addr ex"
    
    def _setup(self):
        self.add_arguemnt("ad_type", "I", argtype=int)
        self.add_argument("address", "Q", argtype=int) # print_ip_ex_address

class Ip(BaseToken):
    """
    ip header 20 bytes
    """
    token_id = AUT_IP
    identifier = "ip"

    def _setup(self):
        self.add_argument("version", "B", argtype=int)
        self.add_argument("tos", "B", argtype=int)
        self.add_argument("len", "H", argtype=int)
        self.add_argument("id", "H", argtype=int)
        self.add_argument("offset", "H", argtype=int)
        self.add_argument("ttl", "B", argtype=int)
        self.add_argument("prot", "B", argtype=int)
        self.add_argument("chksm", "H", argtype=int)
        self.add_argument("src", "I", argtype=int)
        self.add_argument("dest", "I", argtype=int)

class Ipc(BaseToken):
    """
     * object ID type       1 byte
    * Object ID            4 bytes
    """
    token_id = AUT_IPC
    identifier = "ipc"

    def _setup(self):
        self.add_argument("ipc_type", "B", argtype=int)
        self.add_arguemnt("ipc_id", "I", argtype=int)

class IpcPerm(BaseToken):
    """
     * owner user id        4 bytes
    * owner group id       4 bytes
    * creator user id      4 bytes
    * creator group id     4 bytes
    * access mode          4 bytes
    * slot seq                     4 bytes
    * key                          4 bytes
    """
    token_id = AUT_IPC_PERM
    identifier = "IPC perm"

    def _setup(self):
        self.add_argument("uid", "I", argtype=int)
        self.add_argument("gid", "I", argtype=int)
        self.add_argument("puid", "I", argtype=int)
        self.add_argument("pgid", "I", argtype=int)
        self.add_argument("mode", "I", argtype=int)
        self.add_argument("seq", "I", argtype=int)
        self.add_argument("key", "I", argtype=int)


class Iport(BaseToken):
    """
     * port Ip address  2 bytes
    """
    token_id = AUT_IPORT
    identifier = "ip port"

    def _setup(self):
        self.add_argument("port", "H", argtype=int)


class Process32(Subject32):
    """
     * token ID                     1 byte
    * audit ID                     4 bytes
    * euid                         4 bytes
    * egid                         4 bytes
    * ruid                         4 bytes
    * rgid                         4 bytes
    * pid                          4 bytes
    * sessid                       4 bytes
    * terminal ID
    *   portid             4 bytes
    *   machine id         4 bytes
    """
    token_id = AUT_PROCESS32
    identifier = "process"

class Process32Ex(Subject32_Ex):
    """
    * token ID                1 byte
    * audit ID                4 bytes
    * effective user ID       4 bytes
    * effective group ID      4 bytes
    * real user ID            4 bytes
    * real group ID           4 bytes
    * process ID              4 bytes
    * session ID              4 bytes
    * terminal ID
    *   port ID               4 bytes
    *   address type-len      4 bytes
    *   machine address      16 bytes
    """
    token_id = AUT_PROCESS32_EX
    identifier = "process"

class Process64(Subject):
    """
    * token ID                     1 byte
    * audit ID                     4 bytes
    * euid                         4 bytes
    * egid                         4 bytes
    * ruid                         4 bytes
    * rgid                         4 bytes
    * pid                          4 bytes
    * sessid                       4 bytes
    * terminal ID
    *   portid             8 bytes
    *   machine id         4 bytes
    */
    """
    token_id = AUT_PROCESS64
    identifier = "process"

    def _setup(self):
        super()._setup()
        self.add_argument("tid_port", "Q", argtype=int)
        self.add_argument("tid_address", "I", argtype=IPv4Address)

class Process64Ex(Subject):
    """
    * token ID                1 byte
    * audit ID                4 bytes
    * effective user ID       4 bytes
    * effective group ID      4 bytes
    * real user ID            4 bytes
    * real group ID           4 bytes
    * process ID              4 bytes
    * session ID              4 bytes
    * terminal ID
    *   port ID               8 bytes
    *   address type-len      4 bytes
    *   machine address      16 bytes
    """
    token_id = AUT_PROCESS64_EX
    identifier = "process"

    def _setup(self):
        super()._setup()
        self.add_argument("tid_port", "Q", argtype=int)
        self.add_argument("tid_addr_type", "I", argtype=int)
        self.add_argument("tid_address", "2Q", argtype=int)


class Seq(BaseToken):
    token_id = AUT_SEQ
    identifier = "sequence"

    def _setup(self):
        self.add_argument("seqno", "I", argtype=int)


class Socket(BaseToken):
    """
    * socket type             2 bytes
    * local port              2 bytes
    * local address           4 bytes
    * remote port             2 bytes
    * remote address          4 bytes
    """    
    token_id = AUT_SOCKET
    identifier = "socket"

    def _setup(self):
        self.add_argument("sock_type", "H", argtype=int)
        self.add_argument("l_port", "H", argtype=int)
        self.add_arguemnt("l_addr", "I", argtype=IPv4Address)
        self.add_argument("r_port", "H", argtype=int)
        self.add_arguemnt("r_addr", "I", argtype=IPv4Address)
    

class SockInet32(BaseToken):
    """
    * socket family           2 bytes
    * local port              2 bytes
    * socket address          4 bytes
    """
    token_id = AUT_SOCKINET32
    identifier = "socket-inet"

    def _setup(self):
        self.add_argument("family", "H", argtype=int)
        self.add_argument("port", "H", argtype=int)
        self.add_arguemnt("address", "I", argtype=IPv4Address)

#TODO: Complete Token classes
"""
    token_id = AUT_SOCKUNIX:
    token_id = AUT_SOCKINET128:

    token_id = AUT_SOCKET_EX:
    

    token_id = AUT_DATA:
    

    token_id = AUT_ZONENAME:
    

    token_id = AUT_UPRIV:
    

    token_id = AUT_PRIV:
"""
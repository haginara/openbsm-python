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


class Header(BSMStruct):
    __fields__ = [
        ("size", UInt32("size")),
        ("version", UInt8("version")),
        ("event_type", EventType("event_type")),
        ("modifier", UInt16("modifier")),
    ]

class Header32(BSMStruct):
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

    __fields__ = [
        ("_", Header()),
        ("time", DateTime("time")),
        ("msec", MSec("msec")),
    ]

class Header32_Ex(BSMStruct):
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
    identifier = "header"

    __fields__ = [
        ("_", Header()),
        ("address", IPAddress("address")),
        ("time", DateTime("time")),
        ("msec", MSec("msec"))
    ]

class Trailer(BSMStruct):
    """
    trailer magic 2 bytes show=False
    record size   4 bytes
    """

    token_id = AUT_TRAILER
    identifier = "trailer"

    __fields__ = [
        ("magic", UInt16("magic")),
        ("count", UInt32("count")),
    ]

class Argument(BSMStruct):
    """
    * argument #              1 byte
    * argument value          4 bytes/8 bytes (32-bit/64-bit value)
    * text length             2 bytes
    * text                    N bytes + 1 terminating NULL byte
    """

    identifier = "argument"

    __fields__ = [
        ("no", UInt8("no")),
        ("val", UInt32("val")),# Hex
        ("text", String()),
    ]

class Arg32(BSMStruct):
    token_id = AUT_ARG32
    identifier = "argument"

    __fields__ = [
        ("_", Argument()),
    ]


class Arg64(BSMStruct):
    """
       "no": ">b",
        "val": ">Q",
        "text_size": ">H",
        "text": ">{text_size}s",
    """

    token_id = AUT_ARG64
    identifier = "argument"
    
    __fields__ = [
        ("no", UInt8("no")),
        ("val", UInt64("val")),# Hex
        ("text", String()),
    ]
    

class Text(BSMStruct):
    token_id = AUT_TEXT
    identifier = "text"

    __fields__ = [
        ("data", String()),
    ]
    

class Path(BSMStruct):
    token_id = AUT_PATH
    identifier = "path"

    __fields__ = [
        ("data", String()),
    ]


class Return(BSMStruct):
    identifier = "return"

    __fields__ = [
        ("errno", ReturnString("errno")),
    ]
   

class Return32(BSMStruct):
    """
        "errno": ">B",
        "value": ">I",
    """
    token_id = AUT_RETURN32
    identifier = "return"
    
    __fields__ = [
        ("_", Return()),
        ("value", UInt32("value")),
    ]

class Return64(BSMStruct):
    token_id = AUT_RETURN64
    identifier = "return"
    
    __fields__ = [
        ("_", Return()),
        ("value", UInt64("value")),
    ]

class ReturnUuid(BSMStruct):
    """ TODO:
    { 
        struct openbsm_uuid uuid_be;
        int err = 0;

        READ_TOKEN_U_CHAR(buf, len, tok->tt.ret_uuid.no, tok->len, err);
        if (err)
            return (-1);

        READ_TOKEN_BYTES(buf, len, &uuid_be, sizeof(uuid_be), tok->len, err);
        if (err)
            return (-1);
        openbsm_uuid_dec_be(&uuid_be,
            (struct openbsm_uuid *)&tok->tt.ret_uuid.uuid);

        READ_TOKEN_U_INT16(buf, len, tok->tt.ret_uuid.len, tok->len, err);
        if (err)
            return (-1);

        SET_PTR((char*)buf, len, tok->tt.ret_uuid.text, tok->tt.ret_uuid.len,
            tok->len, err);
        if (err)
            return (-1);

        return (0);
    }
    """
    token_id = AUT_RETURN_UUID
    identifier = "ret_uuid"

    __fields__ = [
        ("_", Return()),
        ("size_of_uuid", UInt16("size_of_uuid")),
        ("uuid", String()),
    ]


class Uuid(BSMStruct):
    """
    """
    toekn_id = AUT_ARG_UUID
    identifier = "uuid"

    __fields__ = [
        ("no", UInt8()),
        ("uuid_be", "set_uuid_be"),
        ("uuid", ByteString(length_fmt="H"))
    ]

    def set_uuid_be(self, rec :Rec):
        uuid_fields = [
            ("time_low", UInt32()),
            ("time_mid", UInt16()),
            ("time_hi_and_version", UInt16()),
            ("clock_seq_hi_and_reserved", UInt8()),
            ("clock_seq_low", UInt8()),
        ]
        uuid_struct_fmt = ">"
        size = 0
        for name, field in uuid_fields: 
            uuid_struct_fmt += field.fmt
            size += field.size
        if size > self.no:
            return None
        uuid_struct_fmt += f"{self.no-size}s"
        uuid_fields.append(("node", None))
        uuid = struct.unpack(uuid_struct_fmt, rec.read(self.no))
        return OrderedDict(zip([name for name, _ in uuid_fields], uuid))


class Identity(BSMStruct):
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

    __fields__ = [
        ("signer_type",             UInt32("signer_type")),
        ("signing_id",              String()),
        ("signing_id_truncated",    CompleteString("signing_id_truncated")),
        ("team_id",                 String()),
        ("team_id_truncated",       CompleteString("team_id_truncated")),
        ("cbhash",                  ByteString()),
    ]

class Subject(BSMStruct):
    identifier = "subject"

    __fields__ = [
        ("auid", User("auid")),
        ("euid", User("euid")),
        ("egid", Group("egid")),
        ("ruid", User("ruid")),
        ("rgid", Group("rgid")),
        ("pid", Process("pid")),
        ("sid", UInt32("sid")),
    ]

class Subject32(BSMStruct):
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
    identifier = "subject"

    __fields__ = [
        ("_", Subject()),
        ("tid_port", UInt32("tid_port")),
        ("tid_address", IPv4Address("tid_address")),
    ]

class Subject32_Ex(BSMStruct):
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

    __fields__ = [
        ("_", Subject()),
        ("tid_port", UInt32("tid_port")),
        ("tid_address", IPAddress("tid_address")),
    ]

#TODO: Complete Subject64
class Subject64(BSMStruct):
    token_id = AUT_SUBJECT64
    identifier = "subject"

    __fields__ = [
        ("_", Subject()),
    ]

#TODO: Complete Subject64Ex
class Subject64Ex(BSMStruct):
    token_id = AUT_SUBJECT64_EX
    identifier = "subject_ex"

    __fields__ = [
        ("_", Subject()),
    ]

class Attr(BSMStruct):
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

    __fields__ = [
        ("mode", UInt32("mode")),
        ("uid", User("uid")),
        ("gid", Group("gid")),
        ("fsid", UInt32("fsid")),
        ("nodeid", UInt64("nodeid")),
        ("device", UInt32("device")),
    ]
class Attr32(BSMStruct):
    token_id = AUT_ATTR32
    identifier = "attribute"

    __fields__ = [
        ("_", Attr()),
    ]

class Attr64(BSMStruct):
    token_id = AUT_ATTR64
    identifier = "attribute"

    __fields__ = [
        ("_", Attr()),
    ]


class Opaque(BSMStruct):
    token_id = AUT_OPAQUE
    identifier = "opaque"

    __fields__ = [
        ("data", ByteString())
    ]

class Exit(BSMStruct):
    """
    * status                  4 bytes
    * return value            4 bytes
    """
    token_id = AUT_EXIT
    identifier = "exit"

    __fields__ = [
        ("errval", UInt32("errval")),
        ("retval", UInt32("retval")),
    ]
class ExecArgs(BSMStruct):
    """
    * count                   4 bytes
    * text                    count null-terminated string(s)

    """
    token_id = AUT_EXEC_ARGS
    identifier = "exec arg"

    __fields__ = [
        ("count", UInt32()),
        ("args", "set_args"),
    ]
    def set_args(self, rec: Rec):
        """TODO: Check AUDIT_MAX_ARGS
        for (i = 0; i < tok->tt.execarg.count; i++) {
            bptr = buf + tok->len;
            if (i < AUDIT_MAX_ARGS)
                tok->tt.execarg.text[i] = (char*)bptr;

            /* Look for a null terminated string. */
            while (bptr && (*bptr != '\0'), {
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
        """
        return [String(length_fmt="", until_null=True)(rec) for i in range(self.count.value)]

class ExecEnv(BSMStruct):
    """ TODO:
    """
    token_id = AUT_EXEC_ENV
    identifier = "exec env"

    __fields__ = [
        ("args", Texts("args")),
    ]

class OtherFile(BSMStruct):
    """
    * seconds of time          4 bytes
    * milliseconds of time     4 bytes
    * file name len            2 bytes
    * file pathname            N bytes + 1 terminating NULL byte
    """
    token_id = AUT_OTHER_FILE32
    identifier = "file"

    __fields__ = [
        ("time",        UInt32("time")),
        ("msec",        MSec("msec")),
        ("pathname",    String(with_null=True)),
    ]


class NewGroups(BSMStruct):
    """
    * number groups           2 bytes
    * group list              count * 4 bytes
    """
    token_id = AUT_NEWGROUPS
    identifier = "group"
    
    __fields__ = [
        ("num", UInt16()),
        ("groups", "set_groups"),
    ]

    def set_groups(self, rec: Rec):
        """
        for (i = 0; i<tok->tt.grps.no; i++) {
            READ_TOKEN_U_INT32(buf, len, tok->tt.grps.list[i], tok->len,
                err);
            if (err)
                return (-1);
        }
        """
        return [UInt16.unpack(rec) for i in range(self.num.value)]
    
class InAddr(BSMStruct):
    """
     * Internet addr 4 bytes
    """
    token_id = AUT_IN_ADDR
    identifier = "ip addr"

    __fields__ = [
        ("addr", IPv4Address("addr")),
    ]
class InAddrEx(BSMStruct):
    """
    type 4 bytes
    address 16 bytes
    """
    token_id = AUT_IN_ADDR_EX
    identifier = "ip addr ex"
    
    __fields__ = [
        ("address", IPAddress("address")),
    ]
class Ip(BSMStruct):
    """ TODO:
    ip header 20 bytes
    """
    token_id = AUT_IP
    identifier = "ip"

    __fields__ = [
        ("version",UInt32("version")),
        ("tos",UInt32("tos")),
        ("len",UInt32("len")),
        ("id",UInt32("id")),
        ("offset",UInt32("offset")),
        ("ttl",UInt32("ttl")),
        ("prot",UInt32("prot")),
        ("chksm",UInt32("chksm")),
        ("src",UInt32("src")),
        ("dest",UInt32("dest")),
    ]
class Ipc(BSMStruct):
    """ TODO:
     * object ID type       1 byte
    * Object ID            4 bytes
    """
    token_id = AUT_IPC
    identifier = "ipc"

    __fields__ = [
        ("ipc_type", UInt32("ipc_type")),
        ("ipc_id", UInt32("ipc_id")),
    ]
class IpcPerm(BSMStruct):
    """ TODO:
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

    __fields__ = [
        ("uid",UInt32("uid")),
        ("gid",UInt32("gid")),
        ("puid",UInt32("puid")),
        ("pgid",UInt32("pgid")),
        ("mode", UInt32("mode")),
        ("seq", UInt32("seq")),
        ("key", UInt32("key")),
    ]

class Iport(BSMStruct):
    """ TODO:
     * port Ip address  2 bytes
    """
    token_id = AUT_IPORT
    identifier = "ip port"

    __fields__ = [
        ("port", UInt32("port")),
    ]

class Process32(BSMStruct):
    """ TODO:
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

    __fields__ = [
        ("_", Subject32()),
    ]

class Process32Ex(BSMStruct):
    """ TODO:
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
    
    __fields__ = [
        ("_", Subject32_Ex()),
    ]


class Process64(BSMStruct):
    """ TODO:
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

    __fields__ = [
        ("_", Subject()),
        ("tid_port", UInt64("tid_port")),
        ("tid_address", IPv4Address("tid_address")),
    ]
class Process64Ex(BSMStruct):
    """ TODO:
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

    __fields__ = [
        ("_", Subject()),
        ("tid_port", UInt64("tid_port")),
        ("tid_address", IPAddress("tid_address")),
    ]

class Seq(BSMStruct):
    token_id = AUT_SEQ
    identifier = "sequence"

    __fields__ = [
        ("seqno", UInt32("seqno")),
    ]

class Socket(BSMStruct):
    """
    * socket type             2 bytes
    * local port              2 bytes
    * local address           4 bytes
    * remote port             2 bytes
    * remote address          4 bytes
    """    
    token_id = AUT_SOCKET
    identifier = "socket"

    __fields__ = [
        ("sock_type", UInt16("sock_type")),
        ("l_port", UInt16("l_port")),
        ("l_addr", IPv4Address("l_addr")),
        ("r_port", UInt16("r_port")),
        ("r_addr", IPv4Address("r_addr")),
    ]

class SockInet32(BSMStruct):
    """
    * socket family           2 bytes
    * local port              2 bytes
    * socket address          4 bytes
    """
    token_id = AUT_SOCKINET32
    identifier = "socket-inet"

    __fields__ = [
        ("family", UInt16("family")),
        ("port", UInt16("port")),
        ("address", IPv4Address("address")),
    ]
class SockUnix(BSMStruct):
    """
    * socket family           2 bytes
    * path                    (up to) 104 bytes + NULL (NULL terminated string).
    """
    token_id = AUT_SOCKUNIX
    identifier = "socket-unix"

    __fields__ = [
        ("family", UInt16()),
        ("path", String(length_fmt="", until_null=True, max_length=105)), # String("path", max_len=104, end_with_null=True)
    ]

class SockInet128(BSMStruct):
    """
    * socket family	 2 bytes
    * local port		 2 bytes
    * socket address	16 bytes
    """
    token_id = AUT_SOCKINET128
    identifier = "socket-inet6"

    __fields__ = [
        ("sock_type", UInt16("sock_type")),
        ("port", UInt16("port")),
        ("addr", IPAddress("addr")), # TODO: This field is dynamic field.
    ]


AU_IPv4 = 4
AU_IPv16 = 16
class SocketEx(BSMStruct):
    """
    * socket domain           2 bytes
    * socket type             2 bytes
    * address type            2 bytes
    * local port              2 bytes
    * local Internet address  4/16 bytes
    * remote port             2 bytes
    * remote Internet address 4/16 bytes
    """
    token_id = AUT_SOCKET_EX
    identifier = "socket"

    __fields__ = [
        ("domain", UInt16("domain")),
        ("sock_type", UInt16("sock_type")),
        ("addr_type", UInt16("addr_type")),
        ("l_port", UInt16("l_port")),
        ("l_addr", "set_addr"),  
        ("r_port", UInt16("r_port")),
        ("r_addr", "set_addr"),  
    ]

    def set_addr(self, rec: Rec):
        addr = None
        if self.addr_type.value == AU_IPv4:
            addr = IPv4Address().unpack(rec)
        elif self.addr_type.value == AU_IPv16:
            addr = IPv6Address().unpack(rec)
        else:
            raise Exception(f"Unkonw AddrType: {self.addr_type.value}")

        return addr


class Arb(BSMStruct):
    """
    * how to print            1 byte
    * basic unit              1 byte
    * unit count              1 byte
    * data items              (depends on basic unit)
    """
    token_id = AUT_DATA
    identifier = "arbitrary"

    __fields__ = [
        ("howtopr", UInt8("howtopr")),
        ("bu", UInt8("bu")),
        ("uc", UInt8("uc")),
        ("data", "set_data"),
    ]

    def set_data(self, rec: Rec):
        datasize_dict = {
            AUR_BYTE: AUR_BYTE_FORMAT,
            AUR_SHORT: AUR_SHORT_FORMAT,
            AUR_INT32: AUR_INT32_FORMAT,
            AUR_INT64: AUR_INT64_FORMAT,
        }
        datasize = datasize_dict[self.bu.value]
        fmt = f">{self.uc}{datasize}"
        fmt_length = struct.calcsize(fmt)
        return struct.unpack(fmt, rec.read(fmt_length))

class Zonename(BSMStruct):
    """
    * size                         2 bytes;
    * zonename                     size bytes;
    """
    token_id = AUT_ZONENAME
    identifier = "zone"

    __fields__ = [
        ("zonename", String()),
    ]

class Upriv(BSMStruct):
    """
    * status                       1 byte
    * privstrlen                   2 bytes
    * priv                         N bytes + 1 (\0 byte)
    """
    token_id = AUT_UPRIV
    identifier = "use of privilege"

    __fields__ = [
        ("status", UInt8("status")),
        ("priv", String(with_null=True)),
    ]


class Priv(BSMStruct):
    """
    /*
    * privtstrlen		1 byte
    * privtstr		    N bytes + 1
    * privstrlen		1 byte
    * privstr		    N bytes + 1
    */
    """
    token_id = AUT_PRIV
    identifier = "priv"

    __fields__ = [
        ("privset", String(length_fmt="B", with_null=True)),
        ("privstr", String(length_fmt="B", with_null=True)),
    ]
from datetime import datetime
import pwd
import grp


from .audit_event import get_audit_events
from .bsm_h import *
from .bsm_errors import BSM_ERRORS
from .audit_record import *

from .lib.libproc import proc_pidpath


AUDIT_EVENTS = get_audit_events()

class ArgType(object):
    def __str__(self):
        return self.__repr__()


class EventType(ArgType):
    def __init__(self, event_type):
        self._event_type = AUDIT_EVENTS.get(event_type, "Unknown")

    def __repr__(self):
        return self._event_type.entry


class DateTime(ArgType):
    def __init__(self, timestamp):
        self._datetime = datetime.fromtimestamp(timestamp)

    def __repr__(self):
        return self._datetime.strftime("%c")


class MSec(ArgType):
    def __init__(self, msec):
        self._msec = msec
    
    def __repr__(self):
        return f" + {self._msec} msec"


class ReturnString(ArgType):
    def __init__(self, ret):
        self._ret = ret

    def __repr__(self):
        if self._ret:
            error = (
                f"failure: Unknown error: {self._ret}"
                if self._ret not in BSM_ERRORS
                else f"failure : {BSM_ERRORS.get(self._ret)}"
            )
            return error
        return "success"


class CompleteString(ArgType):
    def __init__(self, ret):
        self._ret = ret

    def __repr__(self):
        return "complete" if self._ret == 0 else "failed"


class String(ArgType):
    def __init__(self, _str):
        self._string = _str[:-1] if _str[-1] == 0 else _str

    def __repr__(self):
        s = self._string.decode("utf-8")
        return s


class ByteString(ArgType):
    def __init__(self, _bytes):
        self._string = _bytes

    def __repr__(self):
        return "0x" + "".join([f"{x:02x}" for x in self._string])


class User(ArgType):
    def __init__(self, uid):
        self._uid = uid

    def __repr__(self):
        try:
            return pwd.getpwuid(self._uid).pw_name
        except:
            return "-1"


class Group(ArgType):
    def __init__(self, gid):
        self._gid = gid

    def __repr__(self):
        return grp.getgrgid(self._gid).gr_name


class IPv4Address(ArgType):
    def __init__(self, intip):
        self._intip = intip

    def __repr__(self):
        return (
            f"{int(self._intip / pow(2, 24)) % 256}."
            f"{int(self._intip / pow(2, 16)) % 256}."
            f"{int(self._intip / pow(2, 8)) % 256}."
            f"{int(self._intip) % 256}"
        )


class Process(ArgType):
    def __init__(self, pid):
        self._pid = pid
    
    def __repr__(self):
        return f"{self._pid}({proc_pidpath(self._pid)})"


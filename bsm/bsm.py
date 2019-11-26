import os
import struct
import logging
import time
import re
from collections import OrderedDict, namedtuple
from datetime import datetime
from typing import List, Dict, Optional, Any, Type, TypeVar

from .audit_event import AUDIT_EVENT, get_audit_events
from .bsm_token import *
from .bsm_h import *
from .audit_record import *
from .argtypes import *

logger = logging.getLogger(__name__)

AUDIT_EVENTS = get_audit_events()

AUDIT_HEADER_SIZE = 18
AUDIT_TRAILER_SIZE = 7


class NotYetImplementedToken(Exception):
    pass


class UnknownHeader(Exception):
    pass


class Record(object):
    DUMP_COM = 0x0000
    DUMP_RAW = 0x0001
    DUMP_SHORT = 0x0002
    DUMP_XML = 0x0004
    DUMP_NORESOLVE = 0x0008
    DUMP_JSON = 0x0010

    def __init__(self, data) -> bytes:
        self.data = data
        self.length = len(data)
        self.bytesread = 0

        self.fetch_tokens()

    def remains(self):
        return self.length - self.bytesread

    def read(self, size) -> bytes:
        start = self.bytesread
        end = start + size
        if end > self.length:
            raise Exception(f"size is bigger than length: {end} > {self.length}")
        self.bytesread += size
        logger.debug(f"start: {start}, end: {end}")
        return self.data[start:end]

    def next_token_id(self) -> int:
        token_id = struct.unpack(">B", self.read(1))[0]
        return token_id

    def fetch_tokens(self):
        self.tokens = []
        while self.bytesread < self.length:
            token_id = self.next_token_id()
            if token_id == 0:
                break
            logger.debug(f"token_id: {token_id}-0x{token_id:x}")
            try:
                token = BSMStruct.get_token(token_id, self)
                logger.debug(f"TOKEN: 0x{token_id:x}: {token}")
                self.tokens.append(token)
            except NotImplementedError:
                raise NotImplementedToken(
                    f"NotImplementedToken: 0x{token_id:x}, reamins: {self.remains()}"
                )
            logger.debug(f"Total: {self.length}, read: {self.bytesread}")

    def print(self, oflags: int):
        for token in self.tokens:
            token.print(oflags)

    def asdict(self):
        """
        """
        # token[0] is Header
        # token[-1] is Trailer
        data = {"record": self.tokens[0].asdict()}
        data["record"].update(
            {token.identifier: token.asdict() for token in self.tokens[1:-1]}
        )
        return data


# AUT_HEADER32, AUT_HEADER32_EX, AUT_HEADER64, AUT_HEADER64_EX
def au_fetch_invalid_tok(record: Record):
    err = 0
    recoversize = record.length - (record.bytesread + AUDIT_TRAILER_SIZE)
    if recoversize <= 0:
        return -1

    invalid_length = recoversize
    # SET_PTR((char*)buf, len, tok->tt.invalid.data, recoversize, tok->len,
    return 0


def au_read_rec(fp, partial: bool = False):
    """ Read Record from audit file

        BSM_TYPE: sizeof(byte)
        SIZE_OF_RECORD: sizeof(uint_32)
        TOKENS: SIZE_OF_RECORD - szieof(BSM_TYPE) - sizeof(SIZE_OF_RECORD)
    """
    # TODO: Partial read
    while True:
        if partial:
            _bsm_type = b"\x14"
            partial = False
        else:
            _bsm_type = fp.read(1)
            if not _bsm_type:
                return
        bsm_type = struct.unpack(">B", _bsm_type)[0]
        if bsm_type in AUT_HEADERS:
            _recsize = fp.read(4)
            recsize = struct.unpack(">I", _recsize)[0]
            if recsize < struct.calcsize(">IB"):
                return None
            logger.debug(
                f"bsm_type: {bsm_type}({struct.calcsize('>B')}),"
                f"recsize: {recsize}({struct.calcsize('>I')}),"
                f"_recsize: {_recsize}"
            )
            # | head32 | head | head | trailer|
            recsize = recsize - struct.calcsize(">BI")
            data = fp.read(recsize)
            yield Record(_bsm_type + _recsize + data)
        elif bsm_type == AUT_OTHER_FILE32:
            # TODO: OTHER_FILE32
            pass
        else:
            # TODO: fetch_invalid_tok
            # sec
            # msec
            # filenamelen

            # type
            # sec
            # msec
            # filenamelen
            # ntohs(filenamelen)
            # buffer = type | sec | msec | filenamelen | noths(filenamelen)
            raise UnknownHeader(f"Unknown header: {bsm_type}")

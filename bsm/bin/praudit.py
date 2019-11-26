#!/usr/bin/env python3
"""
C-vesion: https://github.com/openbsm/openbsm/blob/master/bin/praudit/praudit.c
"""
from ..audit_record import *
from ..bsm import *
from ..bsm_h import *
from ..lib.ioctl import *

import struct
import array
import sys
import os
import pprint
import argparse
import logging

logging.basicConfig(level=logging.INFO)

def get_options(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", help="Specifies the delimiter. The delimiter is the comma.")
    parser.add_argument(
        "-l", action="store_true",
        help="Print the entrire record on the same line. If this option is not specified, every token is displayed on a differnt line.",
    )
    parser.add_argument(
        "-n", action="store_true",
        help="Do not convert user and group IDs to there names but leave in there numeric forms.",
    )

    parser.add_argument(
        "-r",
        dest="raw",action="store_true",
        help="Prints the records in their raw form.  Show records and event types in a numeric form (also known as raw form).  This option is exclusive from -s.",
    )
    parser.add_argument(
        "-s",
        dest="short",action="store_true",
        help="Prints the records in their short form. Show records and events in a short textual representation.  This option is exclusive from -r.",
    )
    parser.add_argument(
        "-x", dest="xml", action="store_true",help="Print audit records in the XML output format."
    )
    parser.add_argument(
        "-j", dest="json", action="store_true", help="Print audit records in the JSON output format."
    )

    parser.add_argument(
        "-p", dest='partial', action="store_true",
        help="Specify this option if input o praudit is piped from tail(1) utility. This cause praudit to sync to the start of the next record.",
    )
    parser.add_argument(
        "-f", dest='filter',
        help=""
    )

    options, args = parser.parse_known_args(argv)
    if len(args) > 0 and os.path.exists(args[0]):
        options.path = args[0]
    else:
        options.path = None
    return options

def get_ioctl_fd(filepath: str):
    """https://www.freebsd.org/cgi/man.cgi?query=auditpipe
    """
    import ctypes
    f = open(filepath, 'rb')
    if not f:
        return -1
    auditPipe = f.fileno()
    selectMode = array.array('i', [0])
    if (ioctl (auditPipe, AUDITPIPE_GET_PRESELECT_MODE, selectMode) < 0):
        return 4
    
    selectMode = array.array('i', [AUDITPIPE_PRESELECT_MODE_LOCAL])
    if (ioctl (auditPipe, AUDITPIPE_SET_PRESELECT_MODE, selectMode, 1) < 0):
        return 4

    selectMode = au_mask_t()
    selectMode.am_success = AUDIT_ALL_fALGS
    selectMode.am_failure = AUDIT_ALL_fALGS
    if (ioctl (auditPipe, AUDITPIPE_SET_PRESELECT_FLAGS, selectMode) < 0):
        return 4
    logger.debug(f"AUDITPIPE_SET_PRESELECT_FLAGS: {AUDITPIPE_SET_PRESELECT_FLAGS:x}, selectMode: {selectMode.am_success}, {selectMode.am_failure}")
    
    selectMode = au_mask_t()
    if (ioctl (auditPipe, AUDITPIPE_GET_PRESELECT_FLAGS, selectMode) < 0):
        return 4

    queueLimitMax = array.array('I', [0])
    if (ioctl (auditPipe, AUDITPIPE_GET_QLIMIT_MAX, queueLimitMax) < 0):
        return 4

    if (ioctl (auditPipe, AUDITPIPE_SET_QLIMIT, queueLimitMax) < 0):
        return 4

    logger.debug(f"auditPipe: {auditPipe}, {f.tell()}")
    return f

def get_fd(filepath: str):
    if filepath == '/dev/auditpipe':
        return get_ioctl_fd(filepath)
    elif filepath is None:
        return sys.stdin.buffer
    return open(filepath, 'rb')
    

def main():
    options = get_options(sys.argv[1:])
    oflags = AU_OFLAG_NONE
    if options.raw:
        oflags |= Record.DUMP_RAW
    elif options.short:
        oflags |= Record.DUMP_SHORT
    elif options.xml:
        oflags |= Record.DUMP_XML
    elif options.json:
        oflags |= Record.DUMP_JSON
    f = get_fd(options.path)
    try:
        if options.partial:
            if options.path is None and f.isatty():
                return -1
            while True:
                _bsm_type = f.read(1)
                bsm_type = struct.unpack(">B", _bsm_type)[0]
                if bsm_type == AUT_HEADER32:
                    break
                if not _bsm_type:
                    return

        if oflags & Record.DUMP_JSON: 
            import json
            for record in au_read_rec(f):
                data = record.asdict() 
                print(json.dumps(data, indent=2))
        else:
            for record in au_read_rec(f, options.partial):
                record.print(oflags)
    finally:
        f.close()

if __name__ == "__main__":
    main()
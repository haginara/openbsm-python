#!/usr/bin/env python3
"""
C-vesion: https://github.com/openbsm/openbsm/blob/master/bin/praudit/praudit.c
"""
from ..audit_record import *
from ..bsm import *
from ..bsm_h import *

import sys
import os
import pprint
import argparse
import logging

logging.basicConfig(level=logging.INFO)

def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", help="Specifies the delimiter. The delimiter is the comma.")
    parser.add_argument(
        "-l",
        help="Print the entrire record on the same line. If this option is not specified, every token is displayed on a differnt line.",
    )
    parser.add_argument(
        "-n",
        help="Do not convert user and group IDs to there names but leave in there numeric forms.",
    )

    parser.add_argument(
        "-r",
        dest="raw",
        help="Prints the records in their raw form.  Show records and event types in a numeric form (also known as raw form).  This option is exclusive from -s.",
    )
    parser.add_argument(
        "-s",
        dest="short",
        help="Prints the records in their short form. Show records and events in a short textual representation.  This option is exclusive from -r.",
    )
    parser.add_argument(
        "-x", dest="xml", help="Print audit records in the XML output format."
    )
    parser.add_argument(
        "-j", dest="json", help="Print audit records in the JSON output format."
    )

    parser.add_argument(
        "-p",
        help="Specify this option if input o praudit is piped from tail(1) utility. This cause praudit to sync to the start of the next record.",
    )
    parser.add_argument("path")

    options = parser.parse_args()
    return options


def main():
    options = get_options()

    oflags = AU_OFLAG_NONE
    if options.raw:
        oflags |= AU_OFLAG_RAW
    elif options.short:
        oflags |= AU_OFLAG_SHORT
    elif options.xml:
        oflags |= AU_OFLAG_XML

    with open(options.path, "rb") as f:
        data = [record.asdict() for record in au_read_rec(f)]
        import json
        print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
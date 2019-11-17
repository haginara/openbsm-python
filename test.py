from audit_record import *
from bsm import *
from bsm_h import *
import sys
import os
import logging

logging.basicConfig(level=logging.INFO)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: program [options] <path>")

    oflags = AU_OFLAG_NONE
    options = sys.argv[1:-1]
    for option in options:
        if option == "-r":
            oflags |= AU_OFLAG_RAW
    path = sys.argv[-1]
    # print(f"oflags: {oflags}, path: {path}")
    with open(path, "rb") as f:
        for record in au_read_rec(f):
            for token in record.tokens:
                token.print(oflags)

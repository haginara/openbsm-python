from audit_record import *
from bsm import *
from bsm_h import *
import sys
import os

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit("Usage: program <path>")

    path = sys.argv[1]
    with open(path, 'rb') as f:
        try:
            for record in au_read_rec(f):
                #print(f"Get Record: {record}")
                for token in au_fetch_tok(record):
                    #print(f"Get Token: {token}")
                    token.print(0)
            #record.print(AU_OFLAG_RAW)
        except Exception as e:
            print(f"Error: {e}")

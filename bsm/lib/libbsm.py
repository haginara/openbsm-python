from ctypes import *
from ctypes import util

bsm = CDLL(util.find_library("bsm"))


funcs = ["au_read_rec", "au_fetch_tok", "au_print_tok", "au_print_flags_tok"]

# tokenstr_t token
with open("/var/audit/20191108061139.not_terminated", "rb") as f:
    buffer = b""
    length = bsm.au_read_rec(f, buffer)
    record_balance = length
    print(length)

    while length > 0:
        token = bsm.au_fetch_tok(token, buffer[processed:], record_balance)
        if token is None:
            break
        print(token)

# Token type identifiers.
AUT_INVALID = 0x00
AUT_OTHER_FILE32 = 0x11
AUT_OHEADER = 0x12
AUT_TRAILER = 0x13
AUT_HEADER32 = 0x14
AUT_HEADER32_EX = 0x15
AUT_DATA = 0x21
AUT_IPC = 0x22
AUT_PATH = 0x23
AUT_SUBJECT32 = 0x24
AUT_XATPATH = 0x25
AUT_PROCESS32 = 0x26
AUT_RETURN32 = 0x27
AUT_TEXT = 0x28
AUT_OPAQUE = 0x29
AUT_IN_ADDR = 0x2A
AUT_IP = 0x2B
AUT_IPORT = 0x2C
AUT_ARG32 = 0x2D
AUT_SOCKET = 0x2E
AUT_SEQ = 0x2F
AUT_ACL = 0x30
AUT_ATTR = 0x31
AUT_IPC_PERM = 0x32
AUT_LABEL = 0x33
AUT_GROUPS = 0x34
AUT_ACE = 0x35
AUT_PRIV = 0x38
AUT_UPRIV = 0x39
AUT_LIAISON = 0x3A
AUT_NEWGROUPS = 0x3B
AUT_EXEC_ARGS = 0x3C
AUT_EXEC_ENV = 0x3D
AUT_ATTR32 = 0x3E
AUT_UNAUTH = 0x3F
AUT_XATOM = 0x40
AUT_XOBJ = 0x41
AUT_XPROTO = 0x42
AUT_XSELECT = 0x43
AUT_XCOLORMAP = 0x44
AUT_XCURSOR = 0x45
AUT_XFONT = 0x46
AUT_XGC = 0x47
AUT_XPIXMAP = 0x48
AUT_XPROPERTY = 0x49
AUT_XWINDOW = 0x4A
AUT_XCLIENT = 0x4B
AUT_CMD = 0x51
AUT_EXIT = 0x52
AUT_ZONENAME = 0x60
AUT_HOST = 0x70
AUT_ARG64 = 0x71
AUT_RETURN64 = 0x72
AUT_ATTR64 = 0x73
AUT_HEADER64 = 0x74
AUT_SUBJECT64 = 0x75
AUT_PROCESS64 = 0x77
AUT_OTHER_FILE64 = 0x78
AUT_HEADER64_EX = 0x79
AUT_SUBJECT32_EX = 0x7A
AUT_PROCESS32_EX = 0x7B
AUT_SUBJECT64_EX = 0x7C
AUT_PROCESS64_EX = 0x7D
AUT_IN_ADDR_EX = 0x7E
AUT_SOCKET_EX = 0x7F
#
# Pre-64-bit BSM, 32-bit tokens weren't explicitly named as '32'.  We have
# compatibility defines.
AUT_HEADER = AUT_HEADER32
AUT_ARG = AUT_ARG32
AUT_RETURN = AUT_RETURN32
AUT_SUBJECT = AUT_SUBJECT32
AUT_PROCESS = AUT_PROCESS32
AUT_OTHER_FILE = AUT_OTHER_FILE32
#
# *
# The values for the following token ids are not defined by BSM.
#
# XXXRW: Not sure how to handle these in OpenBSM yet, but I'll give them
# names more consistent with Sun's BSM.  These originally came from Apple's
# BSM.
AUT_SOCKINET32 = 0x80  # XXX
AUT_SOCKINET128 = 0x81  # XXX
AUT_SOCKUNIX = 0x82  # XXX
#

# Apple specific tokens
AUT_IDENTITY = 0xED
AUT_KRB5_PRINCIPA = 0xEE
AUT_CERT_HAHSH = 0xEF

# print values for the arbitrary token
AUP_BINARY = 0
AUP_OCTAL = 1
AUP_DECIMAL = 2
AUP_HEX = 3
AUP_STRING = 4
#
# data-types for the arbitrary token
AUR_BYTE = 0
AUR_CHAR = AUR_BYTE
AUR_SHORT = 1
AUR_INT32 = 2
AUR_INT = AUR_INT32
AUR_INT64 = 3
#
# ... and their sizes
AUR_BYTE_SIZE = 1  # sizeof(u_char)
AUR_CHAR_SIZE = AUR_BYTE_SIZE
AUR_SHORT_SIZE = 2  # sizeof(uint16_t)
AUR_INT32_SIZE = 4  # sizeof(uint32_t)
AUR_INT_SIZE = AUR_INT32_SIZE
AUR_INT64_SIZE = 8  # sizeof(uint64_t)
#
# Modifiers for the header token
PAD_NOTATTR = 0x4000  # nonattributable event
PAD_FAILURE = 0x8000  # fail audit event
#
AUDIT_MAX_GROUPS = 16
#
# *
# A number of BSM versions are floating around and defined.  Here are
# constants for them.  OpenBSM uses the same token types, etc, used in the
# Solaris BSM version, but has a separate version number in order to
#  identify a potentially different event identifier name space.
AUDIT_HEADER_VERSION_OLDDARWIN = 1  # In = retrospect, a mistake.
AUDIT_HEADER_VERSION_SOLARIS = 2
AUDIT_HEADER_VERSION_TSOL25 = 3
AUDIT_HEADER_VERSION_TSOL = 4
AUDIT_HEADER_VERSION_OPENBSM10 = 10
AUDIT_HEADER_VERSION_OPENBSM11 = 11
AUDIT_HEADER_VERSION_OPENBSM = AUDIT_HEADER_VERSION_OPENBSM11
#
AUT_TRAILER_MAGIC = 0xB105
#
AUT_HEADERS = [AUT_HEADER32, AUT_HEADER32_EX, AUT_HEADER64, AUT_HEADER64_EX]
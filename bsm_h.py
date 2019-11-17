# Size parsed token vectors for execve(2) arguments and environmental
# variables.  Note: changing these sizes affects the ABI of the token
# structure, and as the token structure is often placed in the caller stack,
# this is undesirable.
AUDIT_MAX_ARGS = 128
AUDIT_MAX_ENV = 128

# Arguments to au_preselect(3).
AU_PRS_USECACHE = 0
AU_PRS_REREAD = 1

AU_PRS_SUCCESS = 1
AU_PRS_FAILURE = 2
# AU_PRS_BOTH(AU_PRS_SUCCESS|AU_PRS_FAILURE)

AUDIT_EVENT_FILE = "/etc/security/audit_event"
AUDIT_CLASS_FILE = "/etc/security/audit_class"
AUDIT_CONTROL_FILE = "/etc/security/audit_control"
AUDIT_USER_FILE = "/etc/security/audit_user"

DIR_CONTROL_ENTRY = "dir"
DIST_CONTROL_ENTRY = "dist"
FILESZ_CONTROL_ENTRY = "filesz"
FLAGS_CONTROL_ENTRY = "flags"
HOST_CONTROL_ENTRY = "host"
MINFREE_CONTROL_ENTRY = "minfree"
NA_CONTROL_ENTRY = "naflags"
POLICY_CONTROL_ENTRY = "policy"
EXPIRE_AFTER_CONTROL_ENTRY = "expire-after"
QSZ_CONTROL_ENTRY = "qsize"

AU_CLASS_NAME_MAX = 8
AU_CLASS_DESC_MAX = 72
AU_EVENT_NAME_MAX = 30
AU_EVENT_DESC_MAX = 50
AU_USER_NAME_MAX = 50
AU_LINE_MAX = 256
MAX_AUDITSTRING_LEN = 256
BSM_TEXTBUFSZ = MAX_AUDITSTRING_LEN  # OpenSSH compatibility

# USE_DEFAULT_QSZ-1# Use system default queue size

# Arguments to au_close(3).
AU_TO_NO_WRITE = 0  # Abandon audit record.
AU_TO_WRITE = 1  # Commit audit record.

# Output format flags for au_print_flags_tok().
AU_OFLAG_NONE = 0x0000  # Default form. #/
AU_OFLAG_RAW = 0x0001  # Raw, numeric form. #/
AU_OFLAG_SHORT = 0x0002  # Short form. #/
AU_OFLAG_XML = 0x0004  # XML form. #/
AU_OFLAG_NORESOLVE = 0x0008  # No user/group name resolution. #/


AUT_HEADER32 = 0x14
AUT_HEADER32_EX = 0x15
AUT_HEADER64 = 0x74
AUT_HEADER64_EX = 0x75
AUT_OTHER_FILE32 = 0x11
AUT_OTHER_FILE64 = 0x78

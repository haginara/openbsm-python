#from ioctl_opt import IOC, IO, IOC_READ, IOC_WRITE, IOR, IOW
from fcntl import ioctl
import ctypes
#https://github.com/apple/darwin-xnu/blob/0a798f6738bc1db01281fc08ae024145e84df927/bsd/security/audit/audit_ioctl.h
#/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/usr/include/sys/ioccom.h
AUDITPIPE_IOBASE = ord('A')
AUDITSDEV_IOBASE = ord('S')

##========================================================================================================================
#@(#)ioccom.h	8.2 (Berkeley) 3/28/94
IOCPARM_MASK    = 0x1fff          # parameter length, at most 13 bits
IOCPARM_LEN  = lambda x: (((x) >> 16) & IOCPARM_MASK)
IOCBASECMD   = lambda x: ((x) & ~(IOCPARM_MASK << 16))
IOCGROUP     = lambda x: (((x) >> 8) & 0xff)

IOCPARM_MAX     = IOCPARM_MASK + 1      # max size of ioctl args
# no parameters
IOC_VOID        =  0x20000000
# copy parameters out
IOC_OUT         =  0x40000000
# copy parameters in
IOC_IN          =  0x80000000
# copy paramters in and out
IOC_INOUT       = IOC_IN|IOC_OUT
# mask for IN/OUT/VOID
IOC_DIRMASK     = 0xe0000000

def IOC(inout, group, num, length):
    """
    _IOC(inout, group, num, len) \
	    (inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
    """
    return (inout | ((length & IOCPARM_MASK) << 16) | ((group) << 8) | (num))

def IO(group, num):
    """_IO(g, n)        _IOC(IOC_VOID,	group, num, 0)"""
    return IOC(IOC_VOID, group, num, 0)

def IOR(group, num, ioc_type):
    return IOC(IOC_OUT,	group, num, ctypes.sizeof(ioc_type))

def IOW(group, num, ioc_type):
    return IOC(IOC_IN,	group, num, ctypes.sizeof(ioc_type))

# this should be _IORW, but stdio got there first
def IOWR(group, num, ioc_type):
   return IOC(IOC_INOUT,	group, num, ctypes.sizeof(ioc_type))
##========================================================================================================================


class au_mask_t(ctypes.Structure):
    """
    struct au_mask {
	    unsigned int    am_success;     # Success bits.
	    unsigned int    am_failure;     # Failure bits.
    };
    typedef	struct au_mask	au_mask_t;
    """

    _fields_ = [
        ('am_success', ctypes.c_uint),
        ('am_failure', ctypes.c_uint),
    ]

au_mask = au_mask_t

au_id_t = ctypes.c_uint32

class auditpipe_ioctl_preselect(ctypes.Structure):
    """
    struct auditpipe_ioctl_preselect {
        au_id_t		aip_auid;
        au_mask_t	aip_mask;
    };
    """

    _fields_ = [
        ('au_id_t', au_id_t),
        ('au_mask_t', au_mask_t),
    ]

AUDITPIPE_PRESELECT_MODE_TRAIL = 1
AUDITPIPE_PRESELECT_MODE_LOCAL = 2

#AUDITPIPE_SET_PRESELECT_FLAGS = 0x80084107
#AUDITPIPE_GET_PRESELECT_FLAGS = 0x40084106
#AUDITPIPE_GET_QLIMIT = 0x40044102
##AUDITPIPE_GET_QLIMIT_MAX = 0x40044105
#AUDITPIPE_SET_QLIMIT = 0x80044103
#AUDITPIPE_SET_PRESELECT_NAFLAGS = 0x80084109

AUDITPIPE_GET_QLEN              = IOR(AUDITPIPE_IOBASE, 1, ctypes.c_uint)
AUDITPIPE_GET_QLIMIT            = IOR(AUDITPIPE_IOBASE, 2, ctypes.c_uint)
AUDITPIPE_SET_QLIMIT            = IOW(AUDITPIPE_IOBASE, 3, ctypes.c_uint)
AUDITPIPE_GET_QLIMIT_MIN        = IOR(AUDITPIPE_IOBASE, 4, ctypes.c_uint)
AUDITPIPE_GET_QLIMIT_MAX        = IOR(AUDITPIPE_IOBASE, 5, ctypes.c_uint)
AUDITPIPE_GET_PRESELECT_FLAGS   = IOR(AUDITPIPE_IOBASE, 6, au_mask_t)
AUDITPIPE_SET_PRESELECT_FLAGS   = IOW(AUDITPIPE_IOBASE, 7, au_mask_t)
AUDITPIPE_GET_PRESELECT_NAFLAGS = IOR(AUDITPIPE_IOBASE, 8, au_mask_t)
AUDITPIPE_SET_PRESELECT_NAFLAGS = IOW(AUDITPIPE_IOBASE, 9, au_mask_t)
AUDITPIPE_GET_PRESELECT_AUID    = IOR(AUDITPIPE_IOBASE, 10, auditpipe_ioctl_preselect)
AUDITPIPE_SET_PRESELECT_AUID    = IOW(AUDITPIPE_IOBASE, 11, auditpipe_ioctl_preselect)
AUDITPIPE_DELETE_PRESELECT_AUID = IOW(AUDITPIPE_IOBASE, 12, au_id_t)
AUDITPIPE_FLUSH_PRESELECT_AUID  = IO(AUDITPIPE_IOBASE, 13)
#AUDITPIPE_GET_PRESELECT_MODE   = 0x4004410e
AUDITPIPE_GET_PRESELECT_MODE    = IOR(AUDITPIPE_IOBASE, 14, ctypes.c_int)
#AUDITPIPE_SET_PRESELECT_MODE   = 0x8004410f
AUDITPIPE_SET_PRESELECT_MODE    = IOW(AUDITPIPE_IOBASE, 15, ctypes.c_int)
AUDITPIPE_FLUSH                 = IO(AUDITPIPE_IOBASE, 16)
AUDITPIPE_GET_MAXAUDITDATA      = IOR(AUDITPIPE_IOBASE, 17, ctypes.c_uint)

# Ioctls to retrieve audit pipe statistics.
AUDITPIPE_GET_INSERTS           = IOR(AUDITPIPE_IOBASE, 100, ctypes.c_uint64)
AUDITPIPE_GET_READS             = IOR(AUDITPIPE_IOBASE, 101, ctypes.c_uint64)
AUDITPIPE_GET_DROPS             = IOR(AUDITPIPE_IOBASE, 102, ctypes.c_uint64)
AUDITPIPE_GET_TRUNCATES         = IOR(AUDITPIPE_IOBASE, 103, ctypes.c_uint64)


# Ioctls for the audit session device.
AUDITSDEV_GET_QLEN              = IOR(AUDITSDEV_IOBASE, 1, ctypes.c_uint)
AUDITSDEV_GET_QLIMIT            = IOR(AUDITSDEV_IOBASE, 2, ctypes.c_uint)
AUDITSDEV_SET_QLIMIT            = IOW(AUDITSDEV_IOBASE, 3, ctypes.c_uint)
AUDITSDEV_GET_QLIMIT_MIN        = IOR(AUDITSDEV_IOBASE, 4, ctypes.c_uint)
AUDITSDEV_GET_QLIMIT_MAX        = IOR(AUDITSDEV_IOBASE, 5, ctypes.c_uint)
AUDITSDEV_FLUSH                 =  IO(AUDITSDEV_IOBASE, 6)
AUDITSDEV_GET_MAXDATA           = IOR(AUDITSDEV_IOBASE, 7, ctypes.c_uint)


# Ioctls to retrieve and set the ALLSESSIONS flag in the audit session device.
AUDITSDEV_GET_ALLSESSIONS       = IOR(AUDITSDEV_IOBASE, 100, ctypes.c_uint)
AUDITSDEV_SET_ALLSESSIONS       = IOW(AUDITSDEV_IOBASE, 101, ctypes.c_uint)


# Ioctls to retrieve audit sessions device statistics.
AUDITSDEV_GET_INSERTS           = IOR(AUDITSDEV_IOBASE, 200, ctypes.c_uint64)
AUDITSDEV_GET_READS             = IOR(AUDITSDEV_IOBASE, 201, ctypes.c_uint64)
AUDITSDEV_GET_DROPS             = IOR(AUDITSDEV_IOBASE, 202, ctypes.c_uint64)

# Custom constant variables for ioctl AUDITPIPE_SET_PRESELECT_FLAGS 
AUDIT_INVALID_CLASS             = 0x00000000 # Invalid Class (no)
AUDIT_FILE_READ                 = 0x00000001  # File read (fr)
AUDIT_FILE_WRITE                = 0x00000002  # File write (fw)
AUDIT_FILE_ATTR_ACESS           = 0x00000004  # File attribute access (fa)
AUDIT_FILE_ATTR_MODIFY          = 0x00000008  # File attribute modify (fm)
AUDIT_FILE_CREATE               = 0x00000010  # File create (fc)
AUDIT_FILE_DELETE               = 0x00000020  # File delete (fd)
AUDIT_FILE_CLOSE                = 0x00000040   # File close (cl)
AUDIT_PROCESS                   = 0x00000080  # Process (pc)
AUDIT_NETWORK                   = 0x00000100  # Network (nt)
AUDIT_IPC                       = 0x00000200  # IPC (ip)
AUDIT_NON_ATTR                  = 0x00000400  # Non attributable (na)
AUDIT_ADMINISTRATIVE            = 0x00000800  # Administrative (ad)
AUDIT_LOGIN_LOGOUT              = 0x00001000  # Login/Logout (lo)
AUDIT_AUTH                      = 0x00002000  # Authentication and authorization (aa)
AUDIT_APPLICATION               = 0x00004000  # Application (ap)
AUDIT_IOCTL                     = 0x20000000  # ioctl (io)
AUDIT_EXEC                      = 0x40000000  # exec (ex)
AUDIT_MISC                      = 0x80000000  # Miscellaneous (ot)
AUDIT_ALL_fALGS                 = 0xffffffff  # All flags set (all)

import ctypes 
from .headers import *

#This header file contains private interfaces to obtain process information.  
#These interfaces are subject to change in future releases.
PROC_ALL_PIDS = 1
PROC_PGRP_ONLY = 2
PROC_TTY_ONLY = 3
PROC_UID_ONLY = 4
PROC_RUID_ONLY = 5
PROC_PPID_ONLY = 6

"""
    @define PROC_LISTPIDSPATH_PATH_IS_VOLUME
    @discussion This flag indicates that all processes that hold open
        file references on the volume associated with the specified
        path should be returned.
"""
PROC_LISTPIDSPATH_PATH_IS_VOLUME	= 1


"""
    @define PROC_LISTPIDSPATH_EXCLUDE_EVTONLY
    @discussion This flag indicates that file references that were opened
        with the O_EVTONLY flag should be excluded from the matching
        criteria.
"""
PROC_LISTPIDSPATH_EXCLUDE_EVTONLY	 = 2


"""
    @function proc_listpidspath
    @discussion A function which will search through the current
        processes looking for open file references which match
        a specified path or volume.
    @param type types of processes to be searched (see proc_listpids)
    @param typeinfo adjunct information for type
    @param path file or volume path
    @param pathflags flags to control which files should be considered
        during the process search.
    @param buffer a C array of int-sized values to be filled with
        process identifiers that hold an open file reference
        matching the specified path or volume.  Pass NULL to
        obtain the minimum buffer size needed to hold the
        currently active processes.
    @param buffersize the size (in bytes) of the provided buffer.
    @result the number of bytes of data returned in the provided buffer;
        -1 if an error was encountered;
"""

def _get_libproc():
    return ctypes.CDLL(ctypes.util.find_library("libproc"))

def _get_libproc_func(name, argtypes, restype):
    f = getattr(_get_libproc(), name)
    f.argtypes = argtypes
    f.restype = restype
    return f

def proc_listpidspath(pid_type: int, typeinfo: int, path: str, pathflags: int, buffer: str):
    """
    #int	proc_listpidspath(uint32_t	type,
    #			  uint32_t	typeinfo,
    #			  const char	*path,
    #			  uint32_t	pathflags,
    #			  void		*buffer,
    #			  int		buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
    """
    _proc_listpidspath = _get_libproc_func(
        "proc_listpidspath", 
        [uint32, void_p, uint32, void_p, uint32],
        uint32
    )
    buf = ctypes.create_string_buffer(1024)


def proc_listpids(proc_type):
    #int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
    _proc_listpids = _get_libproc_func(
        "proc_listpids", 
        [uint32, uint32, void_p, uint32],
        uint32
    )
    _proc_listpids



#int proc_listallpids(void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
#int proc_listpgrppids(pid_t pgrpid, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
#int proc_listchildpids(pid_t ppid, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
#int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
#int proc_pidfdinfo(int pid, int fd, int flavor, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
#int proc_pidfileportinfo(int pid, uint32_t fileport, int flavor, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_3);
#int proc_name(int pid, void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
#int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
#int proc_kmsgbuf(void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
def proc_pidpath(pid: int) -> str:
    """int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
    """
    _proc_pidpath = ctypes.CDLL(ctypes.util.find_library("libproc")).proc_pidpath
    _proc_pidpath.argtypes = [uint32, void_p, uint32]
    _proc_pidpath.restype = uint32
    buf = ctypes.create_string_buffer(1024)

    size = _proc_pidpath(pid, buf, len(buf))
    if size != 0:
        return buf.value.decode()
    return ''

#int proc_libversion(int *major, int * minor) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

# Return resource usage information for the given pid, which can be a live process or a zombie.
# Returns 0 on success; or -1 on failure, with errno set to indicate the specific error.
#int proc_pid_rusage(int pid, int flavor, rusage_info_t *buffer) __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);

# A process can use the following api to set its own process control 
# state on resoure starvation. The argument can have one of the PROC_SETPC_XX values
PROC_SETPC_NONE		= 0
PROC_SETPC_THROTTLEMEM	= 1
PROC_SETPC_SUSPEND	 = 2
PROC_SETPC_TERMINATE	= 3

#int proc_setpcontrol(const int control) __OSX_AVAILABLE_STARTING(__MAC_10_6, __IPHONE_3_2);
#int proc_setpcontrol(const int control);

#int proc_track_dirty(pid_t pid, uint32_t flags);
#int proc_set_dirty(pid_t pid, bool dirty);
#int proc_get_dirty(pid_t pid, uint32_t *flags);

#int proc_terminate(pid_t pid, int *sig);
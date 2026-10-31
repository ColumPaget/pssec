#ifndef PSSEC_COMMON_H
#define PSSEC_COMMON_H

#ifdef LIBUSEFUL_BUNDLED
#include "./libUseful-bundled/libUseful.h"
#else
#include "libUseful-5/libUseful.h"
#endif


#include <glob.h>

#define VERSION "2.1"


#define FLAG_THREADED              1 //this means threaded into our internal list of processes, nothing to do with process threads
#define FLAG_NOSU                  2 //process has 'no new privs' set
#define FLAG_SECCOMP               4 //process has seccomp filters
#define FLAG_CHROOT                8 //process is chrooted 
#define FLAG_MEMWX                16 //process has memory that is both writable and executable
#define FLAG_STACKX               32 //process has exectuable stack
#define FLAG_HEAPX                64 //process has executable heap
#define FLAG_TCP                 128 //process has a local TCP socket connection
#define FLAG_RAW                 512 //process has raw socket open
#define FLAG_INET               1024 //process has a remote TCP socket connection
#define FLAG_SERVER             2048 //process is a TCP server
#define FLAG_FDLEAK             4096 //process has many file descriptors open
#define FLAG_LOOP_SERVER        8192 //process is a TCP server, but only on loopback interface
#define FLAG_EXE_PATH          16384 //executable has been deleted
#define FLAG_COMM_NAME         32768 //executable name does not match /proc/<pid>/comm
#define FLAG_EXE_GROUP_WRITE  131072 //executable file is group writable
#define FLAG_EXE_WORLD_WRITE  262144 //exectuable file is world writable
#define FLAG_EXE_SUID         524288 //executable file is suid
#define FLAG_EXE_NAME        1048576 //executable name does not match /proc/<pid>/exe
#define FLAG_SESSION         2097152
#define FLAG_UNREADABLE   2147483648 //some values were unreadable (likely due to permissions)

typedef struct
{
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    uid_t euid;
    pid_t sid;
    size_t threads;
    int Flags;
    char *Name;
		char *CmdLine;
		char *Comm;
    char *ExePath;
    char *User;

    char *FSRoot;
    char *UserNS;
    char *MountNS;
    char *NetNS;
    char *PidNS;
    char *IPCNS;
    char *TimeNS;
    char *UtsNS;

    uint64_t MaxChildren;
    uint64_t MaxMemory;
    uint64_t MaxFiles;
    uint64_t MaxFileSize;

    ListNode *Children;
} TProcess;


extern TProcess *Self;
extern int FDLeakLevel;
extern int PidsDisplayLevel;
extern int FilesDisplayLevel;
extern char *TrustPath;


char *ReadLink(char *RetStr, const char *Dir, const char *File, TProcess *Proc);


#endif

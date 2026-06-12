#ifndef PSSEC_COMMON_H
#define PSSEC_COMMON_H

#ifdef LIBUSEFUL_BUNDLED
#include "./libUseful-bundled/libUseful.h"
#else
#include "libUseful-5/libUseful.h"
#endif


#include <glob.h>

#define VERSION "1.0"


#define FLAG_THREADED  1
#define FLAG_NOSU      2
#define FLAG_SECCOMP   4
#define FLAG_CHROOT    8
#define FLAG_MEMWX    16
#define FLAG_STACKX   32
#define FLAG_SERVER   64
#define FLAG_TCP     128
#define FLAG_RAW     512
#define FLAG_INET   1024
#define FLAG_FDLEAK 4096
#define FLAG_LOOP_SERVER 8192
#define FLAG_UNREADABLE  2147483648

typedef struct
{
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    uid_t euid;
    int Flags;
    char *Name;
    char *User;

    char *FSRoot;
    char *UserNS;
    char *MountNS;
    char *NetNS;
    char *PidNS;
    char *IPCNS;
    char *TimeNS;
    char *UtsNS;

    ListNode *Children;
} TProcess;


extern TProcess *Self;
extern int MaxProcessFD;
extern char *TrustPath;


char *ReadLink(char *RetStr, const char *Dir, const char *File, TProcess *Proc);


#endif

#include "proc.h"
#include "net.h"
#include "proc_list.h"

static void ParseProcStatus(TProcess *Proc, const char *Line)
{
    char *Token=NULL;
    const char *ptr;
    char *tptr;

    ptr=GetToken(Line, ":", &Token, 0);
    if (strcasecmp(Token, "uid")==0) 
    {
	Proc->uid=strtol(ptr, &tptr, 10);
	Proc->euid=strtol(tptr, &tptr, 10);
    }

    if (strcasecmp(Token, "pid")==0) Proc->pid=atol(ptr);
    if (strcasecmp(Token, "ppid")==0) Proc->ppid=atol(ptr);
    if (strcasecmp(Token, "nonewprivs")==0)
    {
        if (atoi(ptr)) Proc->Flags |= FLAG_NOSU;
    }
    if (strcasecmp(Token, "seccomp")==0)
    {
        if (atoi(ptr)) Proc->Flags |= FLAG_SECCOMP;
    }

    Destroy(Token);
}


static void LoadProcFSRoot(TProcess *Proc, const char *Dir)
{
    Proc->FSRoot=ReadLink(Proc->FSRoot, Dir, "/root", Proc);
    if (StrValid(Proc->FSRoot) && (strcmp(Proc->FSRoot, "/") != 0) ) Proc->Flags |= FLAG_CHROOT;
}



static void LoadProcNamespaces(TProcess *Proc, const char *Dir)
{
    Proc->UserNS=ReadLink(Proc->UserNS, Dir, "/ns/user", Proc);
    Proc->MountNS=ReadLink(Proc->MountNS, Dir, "/ns/mnt", Proc);
    Proc->NetNS=ReadLink(Proc->NetNS, Dir, "/ns/net", Proc);
    Proc->PidNS=ReadLink(Proc->PidNS, Dir, "/ns/pid", Proc);
    Proc->IPCNS=ReadLink(Proc->IPCNS, Dir, "/ns/ipc", Proc);
    Proc->TimeNS=ReadLink(Proc->TimeNS, Dir, "/ns/time", Proc);
    Proc->UtsNS=ReadLink(Proc->UtsNS, Dir, "/ns/uts", Proc);
}


static int ConvertAddress(const char *Input, char **IP, char **Port)
{
    char *ptr;
    unsigned long val;

    val=strtol(Input, &ptr, 16);
    *IP=CopyStr(*IP, IPtoStr(val));

    return(TRUE);
}


static void ProcessSocketLine(TProcess *Proc, long Inode, const char *Line, int LocalNetFlag, int NetFlag)
{
    char *Token=NULL, *State=NULL, *LocalIP=NULL, *RemoteIP=NULL;
    const char *ptr;

// sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    ptr=GetToken(Line, "\\S", &Token, 0); //line no

    ptr=GetToken(ptr, "\\S", &Token, 0);  //local address
    ConvertAddress(Token, &LocalIP, NULL);

    ptr=GetToken(ptr, "\\S", &Token, 0);  //remote address
    ConvertAddress(Token, &RemoteIP, NULL);

    ptr=GetToken(ptr, "\\S", &State, 0);  //state
    ptr=GetToken(ptr, "\\S", &Token, 0);  //queue
    ptr=GetToken(ptr, "\\S", &Token, 0);  //tr/tmwhen
    ptr=GetToken(ptr, "\\S", &Token, 0);  //retrnsmt
    ptr=GetToken(ptr, "\\S", &Token, 0);  //uid
    ptr=GetToken(ptr, "\\S", &Token, 0);  //timeout
    ptr=GetToken(ptr, "\\S", &Token, 0);  //inode

    if (atol(Token) == Inode)
    {
        if (IsLocalIP(RemoteIP)) Proc->Flags |= LocalNetFlag;
        else Proc->Flags |= NetFlag;

        //this indicates 'listening' state, and so a server
        if (strcasecmp(State, "0A")==0)
        {
            if (IsLoopbackIP(LocalIP)) Proc->Flags=FLAG_LOOP_SERVER;
            else Proc->Flags |= FLAG_SERVER;
        }
    }

    Destroy(State);
    Destroy(Token);
    Destroy(LocalIP);
    Destroy(RemoteIP);
}



static void ProcessSocket(TProcess *Proc, long Inode, const char *Connections, int LocalNetFlag, int NetFlag)
{
    char *Line=NULL, *Token=NULL;
    const char *ptr;

    ptr=GetToken(Connections, "\n", &Line, 0);
    while (ptr)
    {
        StripLeadingWhitespace(Line);
        ProcessSocketLine(Proc, Inode, Line, LocalNetFlag, NetFlag);
        ptr=GetToken(ptr, "\n", &Line, 0);
    }

    Destroy(Line);
    Destroy(Token);
}




static void CheckProcFDs(TProcess *Proc, const char *Dir)
{
    char *Tempstr=NULL, *TCPNets=NULL, *RawNets=NULL;
    glob_t Glob;
    int i, len;


    Tempstr=MCopyStr(Tempstr, Dir, "/fd/*", NULL);
    if (glob(Tempstr, 0, 0, &Glob) == 0)
    {
        TCPNets=FileRead(TCPNets, "/proc/net/tcp");
        RawNets=FileRead(RawNets, "/proc/net/raw");

        if (Glob.gl_pathc > MaxProcessFD) Proc->Flags |= FLAG_FDLEAK;

        for (i=0; i < Glob.gl_pathc; i++)
        {
            Tempstr=SetStrLen(Tempstr, 4096);
            len=readlink(Glob.gl_pathv[i], Tempstr, 4096);
            if (len > 0)
            {
                StrTrunc(Tempstr, len);
                if (strncmp(Tempstr, "socket:[", 8)==0)
                {
                    ProcessSocket(Proc, atol(Tempstr+8), TCPNets, FLAG_TCP, FLAG_INET);
                    ProcessSocket(Proc, atol(Tempstr+8), RawNets, FLAG_RAW, FLAG_RAW);
                }
            }
        }
    }
    else
    {
	 if ( (errno == EPERM) || (errno == EACCES) ) Proc->Flags |= FLAG_UNREADABLE;
    }


    Destroy(Tempstr);
    Destroy(TCPNets);
    Destroy(RawNets);
}



static void CheckProcExe(TProcess *Proc, const char *Dir)
{



}



static void ParseMemoryMap(TProcess *Proc, const char *Input)
{
    char *Token=NULL;
    const char *ptr;

    ptr=GetToken(Input, "\\S", &Token, 0); //start_addr-end_addr
    ptr=GetToken(ptr, "\\S", &Token, 0);   //protection

//if it contains 'x' then it's executable memory
    if (strchr(Token, 'x'))
    {
        if (strchr(Token, 'w')) Proc->Flags |= FLAG_MEMWX;

        ptr=GetToken(ptr, "\\S", &Token, 0);   //source
        ptr=GetToken(ptr, "\\S", &Token, 0);   //size
        ptr=GetToken(ptr, "\\S", &Token, 0);   //name
        ptr=GetToken(ptr, "\\S", &Token, 0);   //name

        if (strcmp(Token, "[stack]")==0) Proc->Flags |= FLAG_STACKX;
    }

    Destroy(Token);
}




static void LoadProcMemory(TProcess *Proc, const char *Dir)
{
    char *Tempstr=NULL;
    STREAM *S;

    Tempstr=MCopyStr(Tempstr, Dir, "/maps", NULL);
    S=STREAMOpen(Tempstr, "r");
    if (S)
    {
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            ParseMemoryMap(Proc, Tempstr);
            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);
    }

    Destroy(Tempstr);
}


static void ProcLoadCmdLine(TProcess *Proc, const char *Dir)
{
    char *Path=NULL, *Tempstr=NULL;
    int fd, len, i;

    Path=MCopyStr(Path, Dir, "/cmdline", NULL);
    fd=open(Path, O_RDONLY);
    if (fd)
    {
        Tempstr=SetStrLen(Tempstr, 4096);
        len=read(fd, Tempstr, 4096);
        if (len > 0)
        {
            StrTrunc(Tempstr, len);
            for (i=0; i < len; i++)
            {
                if (Tempstr[i] == '\0') Tempstr[i]=' ';
                if (Tempstr[i] == '\\') Tempstr[i]='/';
            }
            Proc->Name=CopyStr(Proc->Name, Tempstr);
        }
        close(fd);
    }

    Destroy(Tempstr);
    Destroy(Path);
}


TProcess *LoadProc(const char *Dir)
{
    STREAM *S;
    char *Tempstr=NULL, *Path=NULL;
    TProcess *Proc=NULL;

    Path=MCopyStr(Path, Dir, "/status", NULL);
    S=STREAMOpen(Path, "r");
    if (S)
    {
        Proc=(TProcess *) calloc(1, sizeof(TProcess));
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            ParseProcStatus(Proc, Tempstr);
            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);

        ProcLoadCmdLine(Proc, Dir);
        LoadProcFSRoot(Proc, Dir);
        LoadProcNamespaces(Proc, Dir);
        LoadProcMemory(Proc, Dir);
        CheckProcFDs(Proc, Dir);
        CheckProcExe(Proc, Dir);
    }


    Destroy(Tempstr);
    Destroy(Path);

    return(Proc);
}




//kernel threads have nothing in their /proc/pid/cmdline
//we use this rather than checking if their /proc/pid/exe
//doesn't link to anything because /proc/pid/exe is often
//unreadable except by root
int IsKernelThread(const char *Path)
{
    char *Tempstr=NULL, *Buffer=NULL;
    int result=FALSE, val;
    STREAM *S;

    Tempstr=MCopyStr(Tempstr, Path, "/cmdline", NULL);
    Buffer=FileRead(Buffer, Tempstr);
    if (! StrValid(Buffer)) result=TRUE;

    Destroy(Tempstr);
    Destroy(Buffer);

    return(result);
}


ListNode *LoadProcs()
{
    ListNode *Procs;
    char *Tempstr=NULL;
    TProcess *Proc;
    glob_t Glob;
    int i;

    Procs=ListCreate();

    glob("/proc/[1-9]*/", 0, 0, &Glob);
    for (i=0; i < Glob.gl_pathc; i++)
    {
        if (! IsKernelThread(Glob.gl_pathv[i]))
        {
            Proc=LoadProc(Glob.gl_pathv[i]);

            Tempstr=FormatStr(Tempstr, "%10d", Proc->pid);
            ListAddNamedItem(Procs, Tempstr, Proc);
        }
    }

    ThreadProcs(Procs);

    Destroy(Tempstr);

    return(Procs);
}



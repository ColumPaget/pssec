#include "common.h"
#include "net.h"
#include "proc.h"

#define ACT_DEFAULT 0
#define ACT_KEY     1
#define ACT_HELP    2
#define ACT_VERSION 3


//process type select flags
#define FLAG_SHOW_SU            1
#define FLAG_SHOW_REMOTE        2
#define FLAG_SHOW_SERVERS       4
#define FLAG_SHOW_MEMWRITE      8
#define FLAG_SHOW_EXE_MISMATCH 16

//display flags
#define FLAG_SHOW_FULLWIDTH 1

int ProcessSelectFlags=0;
int DisplayFlags=0;
pid_t QueryPID=0;


char *DisplayReformatCmdLine(char *RetStr, const char *CmdLine, const char *Pad)
{
    char *Cmd=NULL;
    const char *ptr;

    ptr=GetToken(CmdLine, " ", &Cmd, 0);
    RetStr=MCopyStr(RetStr, Pad, GetBasename(Cmd), " ", ptr, NULL);
    StrTrunc(RetStr, 40);

    Destroy(Cmd);

    return(RetStr);
}



int CheckProcessSelectFlags(TProcess *Proc)
{
    if (! ProcessSelectFlags) return(TRUE);

    if ((ProcessSelectFlags & FLAG_SHOW_SU) && (! (Proc->Flags & FLAG_NOSU))) return(TRUE);
    if ((ProcessSelectFlags & FLAG_SHOW_REMOTE) && (Proc->Flags & FLAG_INET)) return(TRUE);
    if ((ProcessSelectFlags & FLAG_SHOW_SERVERS) && (Proc->Flags & FLAG_SERVER)) return(TRUE);
    if ((ProcessSelectFlags & FLAG_SHOW_MEMWRITE) && (Proc->Flags & (FLAG_MEMWX | FLAG_STACKX | FLAG_HEAPX))) return(TRUE);

    return(FALSE);
}



void DisplayProcesses(STREAM *Term, int wide, ListNode *Items, int Level)
{
    ListNode *Curr, *Next;
    TProcess *Proc;
    char *Tempstr=NULL, *Pad=NULL, *Secure=NULL, *Name=NULL, *User=NULL, *Prefix=NULL;

    Pad=PadStr(Pad, ' ', Level);
    Curr=ListGetNext(Items);
    while (Curr)
    {
        Next=ListGetNext(Curr);
        Proc=(TProcess *) Curr->Item;

        if (CheckProcessSelectFlags(Proc))
        {
            Name=DisplayReformatCmdLine(Name, Proc->CmdLine, Pad);

            if ((Proc->uid == 0) || (Proc->euid == 0) ) User=MCopyStr(User, "~r", LookupUserName(Proc->uid), "~0", NULL);
            else User=CopyStr(User, LookupUserName(Proc->uid));

            Secure=CopyStr(Secure, "");
            if (Proc->Flags & FLAG_UNREADABLE) Secure=CatStr(Secure, "~y????~0 ");
            if (Proc->Flags & FLAG_NOSU) Secure=CatStr(Secure, "~ynosu~0 ");
            if (Proc->Flags & FLAG_SECCOMP) Secure=CatStr(Secure, "~gseccomp~0 ");
            if (Proc->Flags & FLAG_CHROOT) Secure=CatStr(Secure, "~mchroot~0 ");
            if (Proc->Flags & FLAG_STACKX) Secure=CatStr(Secure, "~rstackx~0 ");
            if (Proc->Flags & FLAG_HEAPX) Secure=CatStr(Secure, "~rheapx~0 ");
            if (Proc->Flags & FLAG_MEMWX) Secure=CatStr(Secure, "~rmemwx~0 ");
            if (Proc->Flags & FLAG_LOOP_SERVER) Secure=CatStr(Secure, "~glserver~0 ");
            if (Proc->Flags & FLAG_SERVER) Secure=CatStr(Secure, "~mserver~0 ");
            if (Proc->Flags & FLAG_FDLEAK) Secure=CatStr(Secure, "~mfdleak~0 ");
            if (Proc->Flags & FLAG_TCP) Secure=CatStr(Secure, "~btcp~0 ");
            if (Proc->Flags & FLAG_INET) Secure=CatStr(Secure, "~rtcp~0 ");
            if (Proc->Flags & FLAG_RAW) Secure=CatStr(Secure, "~rraw~0 ");
            if (Proc->Flags & FLAG_COMM_NAME) Secure=MCatStr(Secure, "~rcmd[", GetBasename(Proc->ExePath), "]~0 ", NULL);
            if ((DisplayFlags & FLAG_SHOW_EXE_MISMATCH) && (Proc->Flags & FLAG_EXE_NAME)) Secure=MCatStr(Secure, "~rcmd[", GetBasename(Proc->ExePath), "]~0 ", NULL);
            if (Proc->Flags & FLAG_EXE_PATH) Secure=CatStr(Secure, "~rpath~0 ");
            if (Proc->Flags & FLAG_EXE_GROUP_WRITE) Secure=CatStr(Secure, "~e~rgwrite~0 ");
            if (Proc->Flags & FLAG_EXE_WORLD_WRITE) Secure=CatStr(Secure, "~e~rowrite~0 ");
            if (Proc->Flags & FLAG_EXE_SUID) Secure=CatStr(Secure, "~rsuid~0 ");

            if (StrValid(Proc->UserNS) && (strcmp(Proc->UserNS, Self->UserNS) !=0)) Secure=CatStr(Secure, "~cuserns~0 ");
            if (StrValid(Proc->MountNS) && (strcmp(Proc->MountNS, Self->MountNS) !=0)) Secure=CatStr(Secure, "~cmntns~0 ");
            if (StrValid(Proc->NetNS) && (strcmp(Proc->NetNS, Self->NetNS) !=0)) Secure=CatStr(Secure, "~cnetns~0 ");
            if (StrValid(Proc->PidNS) && (strcmp(Proc->PidNS, Self->PidNS) !=0)) Secure=CatStr(Secure, "~cpidns~0 ");
            if (StrValid(Proc->IPCNS) && (strcmp(Proc->IPCNS, Self->IPCNS) !=0)) Secure=CatStr(Secure, "~cipcns~0 ");
            if (StrValid(Proc->TimeNS) && (strcmp(Proc->TimeNS, Self->TimeNS) !=0)) Secure=CatStr(Secure, "~ctimens~0 ");
            if (StrValid(Proc->UtsNS) && (strcmp(Proc->UtsNS, Self->UtsNS) !=0)) Secure=CatStr(Secure, "~cutsns~0 ");

            if (Proc->MaxChildren < PidsDisplayLevel)
            {
                Tempstr=FormatStr(Tempstr, "~gmpids:%d~0 ", Proc->MaxChildren);
                Secure=CatStr(Secure, Tempstr);
            }

            if (Proc->MaxMemory > 0)
            {
                Tempstr=FormatStr(Tempstr, "~gmmem:%s~0 ", ToIEC(Proc->MaxMemory, 2));
                Secure=CatStr(Secure, Tempstr);
            }

            if (Proc->MaxFiles < FilesDisplayLevel)
            {
                Tempstr=FormatStr(Tempstr, "~gfiles:%s~0 ", ToIEC(Proc->MaxFiles, 2));
                Secure=CatStr(Secure, Tempstr);
            }

            if (Proc->MaxFileSize > 0)
            {
                Tempstr=FormatStr(Tempstr, "~gfsize:%s~0 ", ToIEC(Proc->MaxFileSize, 2));
                Secure=CatStr(Secure, Tempstr);
            }


            if (Proc->Flags & FLAG_SESSION) Prefix=CopyStr(Prefix, "~e");
            else Prefix=CopyStr(Prefix, "");

            User=TerminalPadStr(User, ' ', 15);
            Name=TerminalPadStr(Name, ' ', 40);

            if ((DisplayFlags & FLAG_SHOW_FULLWIDTH) || (wide > 80)) Tempstr=FormatStr(Tempstr, "%s%-8d %s %s~0  %8d  %s\n", Prefix, Proc->pid, User, Name, Proc->threads, Secure);
            else Tempstr=FormatStr(Tempstr, "%s%-8d %s~0 %s\n", Prefix, Proc->pid, Name, Secure);


            TerminalPutStr(Tempstr, Term);
        }

        if (ListSize(Proc->Children)) DisplayProcesses(Term, wide, Proc->Children, Level + 1);

        Curr=Next;
    }

    Destroy(Tempstr);
    Destroy(Secure);
    Destroy(Prefix);
    Destroy(User);
    Destroy(Name);
    Destroy(Pad);
}


void DisplayProcSecurityList()
{
    ListNode *Procs, *Curr;
    STREAM *Term;
    int wide, high;

    Term=STREAMFromDualFD(0, 1);
    TerminalGeometry(Term, &wide, &high);


    Self=LoadProc("/proc/self");
    Procs=LoadProcs(QueryPID);

    Curr=ListGetNext(Procs);
    DisplayProcesses(Term, wide, Procs, 1);
}



int ParseCommandLine(int argc, char *argv[])
{
    CMDLINE *CL;
    const char *arg;
    int Act=ACT_DEFAULT;

    CL=CommandLineParserCreate(argc, argv);

    arg=CommandLineNext(CL);
    while (arg)
    {

        if (strcmp(arg, "--key")==0) Act=ACT_KEY;
        else if (strcmp(arg, "-key")==0) Act=ACT_KEY;
        else if (strcmp(arg, "-fdleak")==0) FDLeakLevel=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "-pdisplay")==0) PidsDisplayLevel=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "-fdisplay")==0) FilesDisplayLevel=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "-pid")==0) QueryPID=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "--pid")==0) QueryPID=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "-S")==0) ProcessSelectFlags |= FLAG_SHOW_SERVERS;
        else if (strcmp(arg, "-servers")==0) ProcessSelectFlags |= FLAG_SHOW_SERVERS;
        else if (strcmp(arg, "--servers")==0) ProcessSelectFlags |= FLAG_SHOW_SERVERS;
        else if (strcmp(arg, "-P")==0) ProcessSelectFlags |= FLAG_SHOW_SU;
        else if (strcmp(arg, "-priv")==0) ProcessSelectFlags |= FLAG_SHOW_SU;
        else if (strcmp(arg, "--priv")==0) ProcessSelectFlags |= FLAG_SHOW_SU;
        else if (strcmp(arg, "-R")==0) ProcessSelectFlags |= FLAG_SHOW_REMOTE;
        else if (strcmp(arg, "-remote")==0) ProcessSelectFlags |= FLAG_SHOW_REMOTE;
        else if (strcmp(arg, "--remote")==0) ProcessSelectFlags |= FLAG_SHOW_REMOTE;
        else if (strcmp(arg, "-M")==0) ProcessSelectFlags |= FLAG_SHOW_MEMWRITE;
        else if (strcmp(arg, "-mem")==0) ProcessSelectFlags |= FLAG_SHOW_MEMWRITE;
        else if (strcmp(arg, "--mem")==0) ProcessSelectFlags |= FLAG_SHOW_MEMWRITE;
        else if (strcmp(arg, "-w")==0) DisplayFlags |= FLAG_SHOW_FULLWIDTH;
        else if (strcmp(arg, "-wide")==0) DisplayFlags |= FLAG_SHOW_FULLWIDTH;
        else if (strcmp(arg, "--wide")==0) DisplayFlags |= FLAG_SHOW_FULLWIDTH;
        else if (strcmp(arg, "-epath")==0) DisplayFlags |= FLAG_SHOW_EXE_MISMATCH;
        else if (strcmp(arg, "--epath")==0) DisplayFlags |= FLAG_SHOW_EXE_MISMATCH;
        else if (strcmp(arg, "--help")==0) Act=ACT_HELP;
        else if (strcmp(arg, "-help")==0) Act=ACT_HELP;
        else if (strcmp(arg, "-?")==0) Act=ACT_HELP;
        else if (strcmp(arg, "-version")==0) Act=ACT_VERSION;
        else if (strcmp(arg, "--version")==0) Act=ACT_VERSION;

        arg=CommandLineNext(CL);
    }


    return(Act);
}


void PrintHelp()
{
    printf("usage:\n");
    printf("  pssec [OPTIONS]\n");
    printf("\noptions:\n");
    printf("  -key             display list of security values\n");
    printf("  --key            display list of security values\n");
    printf("  -fdleak <num>    set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)\n");
    printf("  -pdisplay <num>  limit of 'max pids' that we consider to be constrained, and thus display as a security limit (default 200)\n");
    printf("  -fdisplay <num>  limit of 'max open files' that we consider to be constrained, and thus display as a security limit (default 200)\n");
    printf("  -pid <pid>       only display this pid\n");
    printf("  --pid <pid>      only display this pid\n");
    printf("  -S               only show processes that are network servers\n");
    printf("  -servers         only show processes that are network servers\n");
    printf("  -priv            only show processes that can escalate priviledge (su)\n");
    printf("  -R               only show processes with remote connections open\n");
    printf("  -remote          only show processes with remote connections open\n");
    printf("  -M               only show processes with exectuable memory that is writable, executable stack, or exectuable heap\n");
    printf("  -mem             only show processes with exectuable memory that is writable, executable stack, or exectuable heap\n");
    printf("  -w               display wide output, even if terminal too narrow\n");
    printf("  -wide            display wide output, even if terminal too narrow\n");
    printf("  -epath           display processes whose executable (from /proc/<pid>/exe) does not match their command-line. VERY NOISY.\n");

    printf("  --version        display program version\n");
    printf("  -version         display program version\n");
    printf("  --help           display this help\n");
    printf("  -help            display this help\n");
    printf("  -?               display this help\n");
}




void PrintKey()
{
    TerminalPutStr("Processes with names in ~eBOLD~0 are session leaders. Usernames (if displayed) in red are processes with either the uid or euid set to '0'.\n\n", NULL);
    TerminalPutStr("Process Security Values\n", NULL);
    TerminalPutStr("  ~y????~0           - Some data could not be read. Try re-running pssec as root.\n", NULL);
    TerminalPutStr("  ~ynosu~0           - Process has 'no new privs' flag set to prevent privilege escalation \n", NULL);
    TerminalPutStr("  ~gseccomp~0        - Process has secomp filter set to prevent use of some syscalls \n", NULL);
    TerminalPutStr("  ~mchroot~0         - Process is chrooted to some directory other than system root\n", NULL);
    TerminalPutStr("  ~glserver~0        - Process is a TCP server, but only on LOOPBACK IP (127.x.x.x)\n", NULL);
    TerminalPutStr("  ~mserver~0         - Process is a TCP server\n", NULL);
    TerminalPutStr("  ~cuserns~0         - Process is in a 'user' namespace\n", NULL);
    TerminalPutStr("  ~cmntns~0          - Process is in a 'mount' namespace\n", NULL);
    TerminalPutStr("  ~cnetns~0          - Process is in a 'net' namespace\n", NULL);
    TerminalPutStr("  ~cpidns~0          - Process is in a 'pid' namespace\n", NULL);
    TerminalPutStr("  ~cipcns~0          - Process is in a 'ipc' namespace\n", NULL);
    TerminalPutStr("  ~ctimens~0         - Process is in a 'time' namespace\n", NULL);
    TerminalPutStr("  ~cutsns~0          - Process is in a 'uts' namespace (hostname and domainname)\n", NULL);
    TerminalPutStr("  ~btcp~0            - Process has TCP socket connections open, but only to local IPs\n", NULL);
    TerminalPutStr("  ~rtcp~0            - Process has TCP socket connections open TO REMOTE IPs\n", NULL);
    TerminalPutStr("  ~rraw~0            - Process has RAW socket connections open\n", NULL);
    TerminalPutStr("  ~rmemwx~0          - Process has memory maps that are both writeable and executable, and thus could be open to process injection\n", NULL);
    TerminalPutStr("  ~rstackx~0         - Process has an executable stack\n", NULL);
    TerminalPutStr("  ~rheapx~0          - Process has an executable heap\n", NULL);
    TerminalPutStr("  ~rfdleak~0         - Process has a lot of file descriptors open. Possible fd leak?\n", NULL);
    TerminalPutStr("  ~gmpids:<num>~0    - Process is limited to only have <num> processes. If pid namespace is in use, then this means child processes of the process, otherwise it means total processes run by the user of the process \n", NULL);
    TerminalPutStr("  ~gmmem:<size>~0    - Process is limited to maximum memory of <size> \n", NULL);
    TerminalPutStr("  ~gfiles:<num>~0    - Process is limited to <num> open files \n", NULL);
    TerminalPutStr("  ~gfsize:<size>~0   - Process is limited to maximum file size of <size>\n", NULL);
    TerminalPutStr("  ~rcmd[<name>]~0    - /proc/<pid>/cmdline does not match /proc/<pid>/comm\n", NULL);
    TerminalPutStr("  ~rcmd[<name>]~0    - when used with '-epath' /proc/<pid>/cmdline does not match /proc/<pid>/comm OR executable filename on disk. Very noisy as there's many reasons this can be the case.\n", NULL);
    TerminalPutStr("  ~rpath~0           - running exectuable does not exist on disk (deleted or replaced on disk).\n", NULL);
    TerminalPutStr("  ~e~rgwrite~0         - running exectuable is group writable on disk.\n", NULL);
    TerminalPutStr("  ~e~rowrite~0         - running exectuable is other (WORLD) writable on disk.\n", NULL);
    TerminalPutStr("  ~rsuid~0           - running exectuable is suid or sgid on disk.\n", NULL);

}


void PrintVersion()
{
    printf("pssec: version %s\n", VERSION);
}



int main(int argc, char *argv[])
{
    int Act;
    char *Tempstr=NULL;

    ProcessApplyConfig("mdwe security='paranoid syscall_deny=group:net'");

    TrustPath=CopyStr(TrustPath, "/bin:/usr/bin:/sbin:/usr/sbin");
    Act=ParseCommandLine(argc, argv);

    switch(Act)
    {
    case ACT_HELP:
        PrintHelp();
        break;
    case ACT_KEY:
        PrintKey();
        break;
    case ACT_VERSION:
        PrintVersion();
        break;
    default:
        DisplayProcSecurityList();
        break;
    }

    return(0);
}

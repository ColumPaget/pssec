#include "common.h"
#include "net.h"
#include "proc.h"

#define ACT_DEFAULT 0
#define ACT_KEY     1
#define ACT_HELP    2
#define ACT_VERSION 3




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


void DisplayProcesses(ListNode *Items, int Level)
{
    ListNode *Curr, *Next;
    TProcess *Proc;
    char *Tempstr=NULL, *Pad=NULL, *Secure=NULL, *Name=NULL;

    Pad=PadStr(Pad, ' ', Level);
    Curr=ListGetNext(Items);
    while (Curr)
    {
        Next=ListGetNext(Curr);
        Proc=(TProcess *) Curr->Item;

        Name=DisplayReformatCmdLine(Name, Proc->Name, Pad);

        Secure=CopyStr(Secure, "");
        if (Proc->Flags & FLAG_UNREADABLE) Secure=CatStr(Secure, "~y????~0 ");
        if ((Proc->uid == 0) || (Proc->euid == 0) ) Secure=CatStr(Secure, "~ruid~0 ");
        if (Proc->Flags & FLAG_NOSU) Secure=CatStr(Secure, "~ynosu~0 ");
        if (Proc->Flags & FLAG_SECCOMP) Secure=CatStr(Secure, "~gseccomp~0 ");
        if (Proc->Flags & FLAG_CHROOT) Secure=CatStr(Secure, "~mchroot~0 ");
        if (Proc->Flags & FLAG_STACKX) Secure=CatStr(Secure, "~rstackx~0 ");
        if (Proc->Flags & FLAG_MEMWX) Secure=CatStr(Secure, "~rmemwx~0 ");
        if (Proc->Flags & FLAG_LOOP_SERVER) Secure=CatStr(Secure, "~glserver~0 ");
        if (Proc->Flags & FLAG_SERVER) Secure=CatStr(Secure, "~mserver~0 ");
        if (Proc->Flags & FLAG_FDLEAK) Secure=CatStr(Secure, "~mfdleak~0 ");
        if (Proc->Flags & FLAG_TCP) Secure=CatStr(Secure, "~btcp~0 ");
        if (Proc->Flags & FLAG_INET) Secure=CatStr(Secure, "~rtcp~0 ");
        if (Proc->Flags & FLAG_RAW) Secure=CatStr(Secure, "~rraw~0 ");

        if (StrValid(Proc->UserNS) && (strcmp(Proc->UserNS, Self->UserNS) !=0)) Secure=CatStr(Secure, "~cuserns~0 ");
        if (StrValid(Proc->MountNS) && (strcmp(Proc->MountNS, Self->MountNS) !=0)) Secure=CatStr(Secure, "~cmntns~0 ");
        if (StrValid(Proc->NetNS) && (strcmp(Proc->NetNS, Self->NetNS) !=0)) Secure=CatStr(Secure, "~cnetns~0 ");
        if (StrValid(Proc->PidNS) && (strcmp(Proc->PidNS, Self->PidNS) !=0)) Secure=CatStr(Secure, "~cpidns~0 ");
        if (StrValid(Proc->IPCNS) && (strcmp(Proc->IPCNS, Self->IPCNS) !=0)) Secure=CatStr(Secure, "~cipcns~0 ");
        if (StrValid(Proc->TimeNS) && (strcmp(Proc->TimeNS, Self->TimeNS) !=0)) Secure=CatStr(Secure, "~ctimens~0 ");
        if (StrValid(Proc->UtsNS) && (strcmp(Proc->UtsNS, Self->UtsNS) !=0)) Secure=CatStr(Secure, "~cutsns~0 ");

        Tempstr=FormatStr(Tempstr, "%-10d %-50s %s\n", Proc->pid, Name, Secure);
        TerminalPutStr(Tempstr, NULL);

        if (ListSize(Proc->Children)) DisplayProcesses(Proc->Children, Level + 1);

        Curr=Next;
    }

    Destroy(Tempstr);
    Destroy(Secure);
    Destroy(Name);
    Destroy(Pad);
}


void DisplayProcSecurityList()
{
    ListNode *Procs, *Curr;
    TProcess *Proc;


    Self=LoadProc("/proc/self");
    Procs=LoadProcs();

    Curr=ListGetNext(Procs);
    DisplayProcesses(Procs, 1);
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
        else if (strcmp(arg, "--help")==0) Act=ACT_HELP;
        else if (strcmp(arg, "-help")==0) Act=ACT_HELP;
        else if (strcmp(arg, "-?")==0) Act=ACT_HELP;
        else if (strcmp(arg, "-version")==0) Act=ACT_VERSION;
        else if (strcmp(arg, "--version")==0) Act=ACT_VERSION;
        else if (strcmp(arg, "-f")==0) MaxProcessFD=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "-max-fd")==0) MaxProcessFD=atoi(CommandLineNext(CL));
        else if (strcmp(arg, "--max-fd")==0) MaxProcessFD=atoi(CommandLineNext(CL));
        arg=CommandLineNext(CL);
    }


    return(Act);
}


void PrintVersion()
{
    printf("pssec: version %s\n", VERSION);
}

void PrintHelp()
{
    printf("usage:\n");
    printf("  pssec [OPTIONS]\n");
    printf("\noptions:\n");
    printf("  -f <num>         set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)\n");
    printf("  -max-fd <num>    set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)\n");
    printf("  --max-fd <num>   set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)\n");
    printf("  -key             display list of security values\n");
    printf("  --key            display list of security values\n");
    printf("  --version        display program version\n");
    printf("  -version         display program version\n");
    printf("  --help           display this help\n");
    printf("  -help            display this help\n");
    printf("  -?               display this help\n");
}

void PrintKey()
{
    TerminalPutStr("Process Security Values\n", NULL);
    TerminalPutStr("  ~y????~0        - Some data could not be read. Try re-running pssec as root.\n", NULL);
    TerminalPutStr("  ~ynosu~0        - Process has 'no new privs' flag set to prevent privilege escalation \n", NULL);
    TerminalPutStr("  ~gseccomp~0     - Process has secomp filter set to prevent use of some syscalls \n", NULL);
    TerminalPutStr("  ~mchroot~0      - Process is chrooted to some directory other than system root\n", NULL);
    TerminalPutStr("  ~glserver~0     - Process is a TCP server, but only on LOOPBACK IP (127.x.x.x)\n", NULL);
    TerminalPutStr("  ~mserver~0      - Process is a TCP server\n", NULL);
    TerminalPutStr("  ~cuserns~0       - Process is in a 'user' namespace\n", NULL);
    TerminalPutStr("  ~cmntns~0       - Process is in a 'mount' namespace\n", NULL);
    TerminalPutStr("  ~cnetns~0       - Process is in a 'net' namespace\n", NULL);
    TerminalPutStr("  ~cpidns~0       - Process is in a 'pid' namespace\n", NULL);
    TerminalPutStr("  ~cipcns~0       - Process is in a 'ipc' namespace\n", NULL);
    TerminalPutStr("  ~ctimens~0      - Process is in a 'time' namespace\n", NULL);
    TerminalPutStr("  ~cutsns~0       - Process is in a 'uts' namespace (hostname and domainname)\n", NULL);
    TerminalPutStr("  ~btcp~0         - Process has TCP socket connections open, but only to local IPs\n", NULL);
    TerminalPutStr("  ~rtcp~0         - Process has TCP socket connections open TO REMOTE IPs\n", NULL);
    TerminalPutStr("  ~rraw~0         - Process has RAW socket connections open\n", NULL);
    TerminalPutStr("  ~rmemwx~0       - Process has memory maps that are both writeable and executable, and thus could be open to process injection\n", NULL);
    TerminalPutStr("  ~rstackx~0      - Process has an executable stack\n", NULL);
    TerminalPutStr("  ~rfdleak~0      - Process has a lot of file descriptors open. Possible fd leak?\n", NULL);
    TerminalPutStr("  ~ruid~0         - Process is running as uid or euid 0\n", NULL);
}



main(int argc, char *argv[])
{
    int Act;

    ProcessApplyConfig("security='mdwe:hard paranoid syscall_deny=group:net'");

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
}

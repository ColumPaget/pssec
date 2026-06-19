#include "common.h"


TProcess *Self=NULL;
int FDLeakLevel=200;
int PidsDisplayLevel=200;
int FilesDisplayLevel=200;
char *TrustPath=NULL;


char *ReadLink(char *RetStr, const char *Dir, const char *File, TProcess *Proc)
{
    char *Tempstr=NULL, *Buffer=NULL;
    int len;

    Tempstr=MCopyStr(Tempstr, Dir, "/", File, NULL);
    Buffer=SetStrLen(Buffer, 4096);
    len=readlink(Tempstr, Buffer, 4096);
    if (len < 0)
    {
        Proc->Flags |= FLAG_UNREADABLE;
        len=0;
    }
    StrTrunc(Buffer, len);

    RetStr=CopyStr(RetStr, Buffer);

    Destroy(Tempstr);
    Destroy(Buffer);

    return(RetStr);
}


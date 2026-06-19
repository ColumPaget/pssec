#include "proc_list.h"

static void ThreadProc(ListNode *Procs, TProcess *Proc)
{
    char *Tempstr=NULL;
    ListNode *Node;
    TProcess *Parent;

    Tempstr=FormatStr(Tempstr, "%10d", Proc->ppid);
    Node=ListFindNamedItem(Procs, Tempstr);
    if (Node)
    {
        Parent=(TProcess *) Node->Item;
        if (! Parent->Children) Parent->Children=ListCreate();
        ListAddItem(Parent->Children, Proc);
        Proc->Flags |= FLAG_THREADED;

        if (Proc->sid != Parent->sid) Proc->Flags |= FLAG_SESSION;
    }

    Destroy(Tempstr);
}



void ThreadProcs(ListNode *Procs)
{
    ListNode *Curr, *Next;
    TProcess *Proc;

    Curr=ListGetNext(Procs);
    while (Curr)
    {
        Proc=(TProcess *) Curr->Item;
        ThreadProc(Procs, Proc);
        Curr=ListGetNext(Curr);
    }

    Curr=ListGetNext(Procs);
    while (Curr)
    {
        Next=ListGetNext(Curr);
        Proc=(TProcess *) Curr->Item;
        if (Proc->Flags & FLAG_THREADED) ListDeleteNode(Curr);
        Curr=Next;
    }



}

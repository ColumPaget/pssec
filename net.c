#include "net.h"

int IsLoopbackIP(const char *IP)
{
    if (strncmp(IP, "127.", 4)==0) return(TRUE);

    return(FALSE);
}

int IsLocalIP(const char *IP)
{
    if (strncmp(IP, "0.0.0.0", 7)==0) return(TRUE);
    if (strncmp(IP, "127.", 4)==0) return(TRUE);
    if (strncmp(IP, "192.168.", 8)==0) return(TRUE);
    if (strncmp(IP, "10.", 3)==0) return(TRUE);
    if (strncmp(IP, "172.16.", 7)==0) return(TRUE);

    return(FALSE);
}



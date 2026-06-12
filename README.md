title: cxine
mansection: 1
date: 2020/05/21


SYNOPSIS
========

pssec is a simple tool that displays some security features (or issues) active on running processes

USAGE
=====

```
  pssec [OPTIONS]
```


OPTIONS
=======

-f <num>
: set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)
-max-fd <num>    
: set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)
--max-fd <num>   
: set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)
-key             
: display list of security values
--key
: display list of security values
--version
: display program version
-version
: display program version
--help
: display this help
-help
: display this help
-?
: display this help



OUTPUT
======

Currently, against each process, pssec can display the following values:


????
: Some data could not be read. Try re-running pssec as root.

nosu
: Process has 'no new privs' flag set to prevent privilege escalation 

seccomp
: Process has secomp filter set to prevent use of some syscalls 

chroot
: Process is chrooted to some directory other than system root

lserver
: Process is a TCP server, but only on LOOPBACK IP (127.x.x.x)

server
: Process is a TCP server

userns
: Process is in a 'user' namespace

mntns
: Process is in a 'mount' namespace

netns
: Process is in a 'net' namespace

pidns
: Process is in a 'pid' namespace

ipcns
: Process is in a 'ipc' namespace

timens
: Process is in a 'time' namespace

utsns
: Process is in a 'uts' namespace (hostname and domainname)

tcp
: Process has TCP socket connections open, but only to local IPs

tcp
: Process has TCP socket connections open TO REMOTE IPs

raw
: Process has RAW socket connections open

memwx
: Process has memory maps that are both writeable and executable, and thus could be open to process injection

stackx
: Process has an executable stack

fdleak
: Process has a lot of file descriptors open. Possible fd leak?

uid
: Process is running as uid or euid 0



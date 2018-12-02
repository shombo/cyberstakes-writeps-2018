from pwn import *

p = remote('challenge.acictf.com','31802')

p.recvuntil('-\n')

d = {
    'right': '>',
    'left': '<',
    'down': 'V',
    'up': '^',
}

for _ in range(40):
    p.sendline(d[p.recvline().strip()])
    p.recvline()

print p.recvall()
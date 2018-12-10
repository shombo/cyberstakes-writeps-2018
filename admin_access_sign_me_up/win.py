from pwn import *
import hashpumpy

x = 33
sig, auth_code = hashpumpy.hashpump('6637e58f2e62b71fd4dd5e32f50fa58b1bbd33c11f04ebfa4e7b5ba26d4279248057fee587a9ac93b1c65076676c5ff6ddb5179bfb77fb3c8bc2f628f3f0f0f6','a',':admin',x)
auth_code = auth_code.encode('hex')
p = remote('challenge.acictf.com', 20261,level="error")
p.recvuntil(': ')
p.sendline('2')
p.recvuntil(':')
p.sendline(auth_code)
p.recvuntil(':')
p.sendline(sig)
print x, p.recvline()
p.close() 

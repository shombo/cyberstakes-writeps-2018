# Want some PIE? - Points: 200

### Description:

It seems the enemy has figured out how to turn on ASLR, but they still don't know how to properly code. Compromise the server and steal the flag. Listening on challenge.acictf.com:1752, binary: registrar, libc: libc.so

### Hints

 - Have you completed 'Say as I say, not as I do' yet? Solve that one first.
 - Since ASLR is enabled, you'll need to find a way to leak some interesting details about where things are located in memory.
 - Even with ASLR in place, libc is still a good source of ROP gadgets and utility functions.

### Solution

Format string to read the stack cookie, and one_gadget for an easy shell

### Flag: `TODO`

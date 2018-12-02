# Byte Sized CBC - Points: 50

### Description:

Break the CBC 'encryption' scheme running at challenge.acictf.com:1751. The author is so confident that they will just hand you the key upon connection.

### Hints

 - Cipher Block Chaining ties the output of each block's 'encryption' to the next block.
 - How many different IVs could there be if a block is only one byte long?
 - What if the 'block cipher' [link](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:CBC_encryption.svg) doesn't do anything?

### Solution

There are lots of good diagrams of CBC mode out there. Generally, this is a mode of a particular encryption scheme. Generally, this type of encryption must be a multiple of a specified `block size` (if the message isn't, it will be padded with junk data so that it is). Then, for each `block`, the result of the previous encryption block will be XORed with the plain text block prior to that XORed chunk being put through some encrpytion scheme (this step usually takes in some key). Once that step is complete, you now have an encrypted block and serves as part of the encrypted outpput and an input to the next next round. On the very first round, there obviously has not been a previous round so, therefore, you don't have that special value to XOR your plain text with prior to the encryption step. Instead of using the output from the previous step, you just give it a special number instead knows as the `initialization vector`.

If this sounds complicated, just google a picture. 

But since you need an `initialization vector` to kick eveything off, and every next round is a product of the previous round, the `initialization vector`, or `iv`, is pretty crucial in being able to recover an encrypted message.

Luckily, in this particular challenge, we are only dealing with a block size of a single byte. Also, since no encryption scheme was specified, and I'm too lazy to try to guess one. so I am going to assume that they jsut didn't use one.

What does this mean?

This means that the first letter of the flag was XORed with some IV. Then, the resulting character was emitted, but also used as the key for the next round.

Assuming this is true, it should be somewhat trivial to recover what the `key` for each round was since XOR is an invertable operation. (A ^ B = C, A ^ C == B)

Finally firing up the challenge:

    shombo$ nc challenge.acictf.com 1751
    Welcome to the Byte Sized CBC Challenge!
    Your Encrypted Flag (in Base64): rO+m3b6I7N3t3O6L6tO1hbDTsNHp3+yIvd7ujezfvsPJ

An important note here is that the data is given in base64. That simply means that the raw bytes you ought to be dealing with have been encoded into a format that transmitter easier.


    shombo$ python
    Python 2.7.15 (default, Jun 17 2018, 12:46:58) 
    [GCC 4.2.1 Compatible Apple LLVM 9.1.0 (clang-902.0.39.2)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import base64
    >>> base64.b64decode('rO+m3b6I7N3t3O6L6tO1hbDTsNHp3+yIvd7ujezfvsPJ')
    '\xac\xef\xa6\xdd\xbe\x88\xec\xdd\xed\xdc\xee\x8b\xea\xd3\xb5\x85\xb0\xd3\xb0\xd1\xe9\xdf\xec\x88\xbd\xde\xee\x8d\xec\xdf\xbe\xc3\xc9'


At this point, it is really important to understand that we need to _reverse_ this encrypted message -- we won't be able to generate it in the forward direction easily. I suppose we could brute force every byte, but that sounds hard. Let's do it the easy way... *backwards*!

Why do it backwards?

Well, we know what the result of a given round is... its whatever the byte at the position is. We also know what it was XORed with -- it was whatever the preceding byte is. If we XOR those two things together, we should the third piece of the equation remainging -- the plaintext.We only don't know what the very first byte was XORed with, but we also don't care since we're 98% sure it was an `A`.

Let's put this theory to the test.

The last encrypted character is `\xc9` and the previous character is `\xc3`.

    >>> chr(0xc3 ^ 0xc9)
    '\n'

Hmm.. ok..

Let's keep going.. the next encrypted character back is `\xbe`. So, let's XOR that with the current encrypted char (`\xc3`):

    >>> chr(0xbe ^ 0xc3)
    '}'

Oh boy.. that looks like the end of the flag!

Let's script it up and see what we get...

    >>> flag = base64.b64decode('rO+m3b6I7N3t3O6L6tO1hbDTsNHp3+yIvd7ujezfvsPJ')
    >>> print ''.join([chr(ord(flag[x]) ^ ord(flag[x-1])) for x in range(len(flag)-1,0,-1)])[::-1]
    CI{c6d1012ea9f05cca863d5c0ca3a}

We skipped the first letter since we didn't know what to XOR it with, but it pretty clearly looks like its supposed to be an `A`.


### Flag: `ACI{c6d1012ea9f05cca863d5c0ca3a}`


# Ascii Salad - Points: 50

### Description:

Cobra Commander is sending a flag to one of his goons. Break their simple code to find the flag here challenge.acictf.com:61703.
Example connection command: nc challenge.acictf.com 61703

### Hints

 - Cobra Commander thinks a lot of himself... its reasonable he would use a classic cipher named after an emperor.
 - Clearly these guys are using more characters than just the alphabet -- is there a chart with lots of possible characters on it?
 - The order of the characters on the chart matters, just like the order of the letters in the alphabet for the classic cipher. Can you identify good start and end points on the chart to rotate around?
 - Even with more characters than the alphabet, there are not THAT many options. Could you brute force their weak scheme?

### Solution

I felt like this challenge was a little guessy and kind of stupid. The hard part of the challenge is guessing the right thing that they want you to do and not actually working towards anything. Anyway... Let's interactive with the service:

    shombo$ nc challenge.acictf.com 61703
    Message: +-3e{"O}M""yL| " }} {PyyzK{P|P|g

Alright.. intuition tells me that this is some kind of caesar cipher type deal. Let's write a quick script to check it out...

    shombo$ python
    Python 2.7.15 (default, Jun 17 2018, 12:46:58) 
    [GCC 4.2.1 Compatible Apple LLVM 9.1.0 (clang-902.0.39.2)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    >>> for i in range(0xff):
    ...   print i, ''.join([chr(ord(x) + i) for x in '+-3e{"O}M""yL| " }} {PyyzK{P|P|g'])
    <snip>
    21 @BHz?7d?b77?a?575??5?e???`?e?e?|
    22 ACI{?8e?c88?b?686??6?f???a?f?f?}
    23 BDJ|?9f?d99?c?797??7?g???b?g?g?~
    <snip>

Ok, this looks promising. But why isn't it complete?

It must be because some of the values at > 127 and therefor out of ascii range. Hmm.

I know what you're thinking.. lets just mod everything by 128. That's a reasonable idea, except that there are a lot of nonprintable characters in the beginning of the ascii range. Looking at the ascii table, let's mod everything by 128, but if the value ends up being < 32, we will simply add 32 to keep everything in printable range.

    out = ''
    for ch in '+-3e{"O}M""yL| " }} {PyyzK{P|P|g':
        val = (ord(ch) + 22) % 128
        if val < 32:
            val += 32
        out += chr(val)

    print out

### Flag: `ACI{18e3c88/b26863361f//0a1f2f2}`


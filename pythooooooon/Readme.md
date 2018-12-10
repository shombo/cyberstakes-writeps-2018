# Pythoooooooooon - Points: 200

### Description:



### Hints



### Solution

A fairly simply python challenge. You are given a socket and obfuscated encryption code. When you connect to a socket, the socket gives you the encrypted text. You can rather quickly and programmatically de-obfuscate this code with find/replace, but it is unnecessary if you look at the core functions. First, there are a whole bunch of functions that call `return ooo(o, oooooooo('o'*<some int>))`. Let's look at these sub functions.

```
def ooo(o, oo):
    return [ oooooo(ooooo(oooo) ^ oo) for oooo in o ]

def ooooo(o):
    return ord(o)

def oooooo(o):
    return chr(o)
```

The bottom two are pretty easy. `ooooo()` is simply `ord()` and `oooooo()` is simply `chr()`. Replacing those, we get:

```
def ooo(o, oo):
    return [ chr(ord(oooo) ^ oo) for oooo in o ]
```

which can be rewritten (with more appropriate value names) as:

```
def ooo(encoded_string, int_val):
  new_msg = ""
  for char in encoded_string:
    result += chr(ord(char) ^ int_val)
  return new_msg
```
which is fairly easily recognized as the `xor` function of a string against a single int (the length of the many different 'o' string). We know that a^b=c and c^a=b (or ^b=a). As such, we do not even need to reverse this function. Simply re-run the encryption function on the provided base64 decoded encrypted string to recover the original flag.

### Flag: `ACI{90a1e621e56074433289ceadb1c}`

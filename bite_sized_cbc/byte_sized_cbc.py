#!/usr/bin/env python2
from base64 import b64decode

ciphertext = "j8yF/p2rz/7O/82oyfCWppPwk/LK/M+rnv3Nrs/8neD"
cipher_bytes = b64decode(ciphertext + "=")

plaintext = ""
for i in range(1, len(cipher_bytes)):
   plaintext += chr(cipher_bytes[i-1] ^ cipher_bytes[i])
print(plaintext)




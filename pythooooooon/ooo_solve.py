#!/usr/bin/env python3
import sys
import base64

# subtract ten from o-length to get index
xor_values = [92, 222, 26, 183, 245, 254, 161, 196, 38, 200,
        194, 170, 43, 104, 103, 253, 152, 183, 215, 221, 97,
        60, 197, 145, 74]

obf_string = "ooooooooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooooooooo(ooooooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooooooo(ooooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooooo(ooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooo(ooooooooooooooooooooooooooo(oooooooooooooooooooooooooo(ooooooooooooooooooooooooo(ooooooooooooooooooooooo(oooooooooooooooooooooo(ooooooooooooooooooooo(oooooooooooooooooooo(ooooooooooooooooooo(oooooooooooooooooo(ooooooooooooooooo(oooooooooooooooo(ooooooooooooooo(oooooooooooooo(ooooooooooooo(oooooooooooo(ooooooooooo(oooooooooo"

flag = "OTsxAxtMSkAbHRlJSR0ZSk0ZHUsZTR4eSksZHh1NGwU="
flag_dec = base64.b64decode(flag)
final = flag_dec.decode('utf-8')
for xor_value in reversed(xor_values):
    intermediate = ""
    for i in range(len(flag_dec)):
        intermediate += (chr(ord(final[i]) ^ xor_value))
    final = intermediate
print(final)

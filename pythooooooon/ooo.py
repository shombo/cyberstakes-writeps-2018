#!/usr/bin/env python3

import base64

def oooooooooo(o):
	return ooo(o, oooooooo('o'*92))

def ooooooooooo(o):
	return ooo(o, oooooooo('o'*222))

def oooooooooooo(o):
	return ooo(o, oooooooo('o'*26))

def ooooooooooooo(o):
	return ooo(o, oooooooo('o'*183))

def oooooooooooooo(o):
	return ooo(o, oooooooo('o'*245))

def ooooooooooooooo(o):
	return ooo(o, oooooooo('o'*254))

def oooooooooooooooo(o):
	return ooo(o, oooooooo('o'*161))

def ooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*196))

def oooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*38))

def ooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*200))

def oooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*194))

def ooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*170))

def oooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*43))

def ooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*104))

def ooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*103))

def oooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*253))

def ooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*152))

def oooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*183))

def ooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*215))

def oooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*221))

def ooooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*97))

def oooooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*60))

def ooooooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*197))

def oooooooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*145))

def ooooooooooooooooooooooooooooooooooo(o):
	return ooo(o, oooooooo('o'*74))

def ooo(o, oo):
    return [ oooooo(ooooo(oooo) ^ oo) for oooo in o ]

def ooooo(o):
    return ord(o)

def oooooo(o):
    return chr(o)

def ooooooo(o):
    return ''.join(ooooooooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooooooooo(ooooooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooooooo(ooooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooooo(ooooooooooooooooooooooooooooo(oooooooooooooooooooooooooooo(ooooooooooooooooooooooooooo(oooooooooooooooooooooooooo(ooooooooooooooooooooooooo(ooooooooooooooooooooooo(oooooooooooooooooooooo(ooooooooooooooooooooo(oooooooooooooooooooo(ooooooooooooooooooo(oooooooooooooooooo(ooooooooooooooooo(oooooooooooooooo(ooooooooooooooo(oooooooooooooo(ooooooooooooo(oooooooooooo(ooooooooooo(oooooooooo(o))))))))))))))))))))))))))

def oooooooo(o):
    return len(o)

eo = base64.b64encode(bytes(ooooooo(open("flag.txt", "r").read().strip()), 'utf-8')).decode('utf-8')

print("The flag has been protected: {}".format(eo))
print("Can you recover it?")

import base64


def a(x):
    # use 92 as key
    return xor(x, get_len(' ' * 92))

def b(x):
    # use 222 as key
    return xor(x, get_len(' ' * 222))

def c(x):
    # use26 as key
    return xor(x, get_len(' ' * 26))

def d(x):
    # use 92 as key
    return xor(x, get_len(' ' * 183))

def e(x):
    # use 222 as key
    return xor(x, get_len(' ' * 245))

def f(x):
    # use26 as key
    return xor(x, get_len(' ' * 254))

def g(x):
    # use 92 as key
    return xor(x, get_len(' ' * 161))

def h(x):
    # use 222 as key
    return xor(x, get_len(' ' * 196))

def i(x):
    # use26 as key
    return xor(x, get_len(' ' * 38))

def j(x):
    # use 92 as key
    return xor(x, get_len(' ' * 200))

def k(x):
    # use 222 as key
    return xor(x, get_len(' ' * 194))

def l(x):
    # use26 as key
    return xor(x, get_len(' ' * 170))

def m(x):
    # use 92 as key
    return xor(x, get_len(' ' * 43))

def n(x):
    # use 222 as key
    return xor(x, get_len(' ' * 104))

def o(x):
    # use26 as key
    return xor(x, get_len(' ' * 103))

def p(x):
    # use 92 as key
    return xor(x, get_len(' ' * 253))

def q(x):
    # use 222 as key
    return xor(x, get_len(' ' * 152))

def r(x):
    # use26 as key
    return xor(x, get_len(' ' * 183))

def s(x):
    # use 92 as key
    return xor(x, get_len(' ' * 215))

def t(x):
    # use 222 as key
    return xor(x, get_len(' ' * 221))

def u(x):
    # use26 as key
    return xor(x, get_len(' ' * 97))

def v(x):
    # use 92 as key
    return xor(x, get_len(' ' * 60))

def w(x):
    # use 222 as key
    return xor(x, get_len(' ' * 197))

def x(y):
    # use26 as key
    return xor(y, get_len(' ' * 145))

def y(x):
    # use26 as key
    return xor(x, get_len(' ' * 74))

def xor(list_x, key):
    # ooo
    return [get_chr(get_ord(ch) ^ key) for ch in list_x]

def get_ord(x):
    # ooooo
    return ord(x)

def get_chr(x):
    # oooooo
    return chr(x)

#def encode(z)
#    return ''.join(y(x(w(v(u(t(s(r(q(p(o(n(m(l(k(j(i(h(g(f(e(d(c(b(a(z))))))))))))))))))))))))))

def decode(z):
    return ''.join(a(b(c(d(e(f(g(h(i(j(k(l(m(n(o(p(q(r(s(t(u(v(w(x(y(z))))))))))))))))))))))))))

def get_len(x):
    # oooooooo
    return len(x)


if __name__ == '__main__':
    flag = 'OTsxAxtMSkAbHRlJSR0ZSk0ZHUsZTR4eSksZHh1NGwU='
    print decode(base64.b64decode(flag))

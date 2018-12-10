def chunks(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in xrange(0, len(l), n))

if __name__ == "__main__":
    for i in range(8):
        i = bin(i).split('b')[1].zfill(3)
        a = '00110111100000000100111101011000111110110011010001110000101101110100110010011011110011110001101000001001011111111000100101001'.replace(' ','')
        a = a + i

        c = chunks(a,8)
        print ''.join([chr(int(y,2) ) for y in c]).encode('hex')[:32]



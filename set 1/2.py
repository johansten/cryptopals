
def xor_strings(a, b):
	res = int(a, 16) ^ int(b, 16)
	return '{:x}'.format(res)

s1 = "1c0111001f010100061a024b53535009181c"
s2 = "686974207468652062756c6c277320657965"
print xor_strings(s1, s2)




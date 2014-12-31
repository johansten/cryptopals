
import cryptopals
import random


def encrypt_mt(raw, seed):

	res = []

	mt = cryptopals.MersenneTwister()
	mt.seed(seed)

	for p in raw:
		p = ord(p) ^ (mt.rand_int32() & 255)
		res.append(chr(p))

	return ''.join(res)


def random_pad(s):
	return cryptopals.get_random_key(1, 20) + s


plain_text = '.' * 14
seed = random.randint(1, 65535)
cipher_text = encrypt_mt(plain_text, seed)

for n in xrange(0, 65535):

	test = encrypt_mt(cipher_text, n)
	if test[-14:] == plain_text:
		print "Seed:", n
		break

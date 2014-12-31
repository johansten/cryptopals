
import cryptopals
import random


def encryption_oracle(s):

	s = "%s%s%s" % (
		cryptopals.get_random_key(5, 10),
		s,
		cryptopals.get_random_key(5, 10)
	)

	s = cryptopals.pkcs7_pad(s, 16)

	#

	key = cryptopals.get_random_key(16)
	if random.randint(0, 1):
		c = cryptopals.encrypt_cbc(s, key, cryptopals.get_random_key(16))
	else:
		c = cryptopals.encrypt_ebc(s, key)

	return c


c = encryption_oracle('\0'*48)
if cryptopals.is_ecb(c):
	print "ebc"
else:
	print "cbc"

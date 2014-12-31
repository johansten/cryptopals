
import cryptopals
import base64
import itertools

_raw = (
	"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG"
	"Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll"
	"cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ"
	"pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.raw = base64.standard_b64decode(_raw)

	def encrypt(self, s):
		s = s + self.raw
		s = cryptopals.pkcs7_pad(s, 16)
		c = cryptopals.encrypt_ebc(s, self.key)
		return c

api = Api()


def get_block_size():

	l0 = len(api.encrypt(''))
	for n in itertools.count():
		l = len(api.encrypt('.' * n))
		if l != l0:
			break

	return l - l0


def process_block(prefix, block_index, block_size):

	plain_text = ''
	for pad_size in xrange(block_size - 1, -1, -1):

		prefix = prefix[1:]

		lookup = {}
		for n in xrange(256):
			s = prefix + chr(n)
			c = api.encrypt(s)[:block_size]
			lookup[c] = chr(n)

		offset = block_size * block_index
		c = api.encrypt('.' * pad_size)[offset:offset + block_size]
		if c not in lookup:
			break

		found = lookup[c]
		plain_text += found
		prefix += found

	return plain_text

#

block_size = get_block_size()
num_blocks = len(api.encrypt('')) / block_size

#

prefix = '.' * 16

res = []
for block_index in xrange(num_blocks):
	plain_text = process_block(prefix, block_index, block_size)
	res.append(plain_text)
	prefix = plain_text

print ''.join(res)

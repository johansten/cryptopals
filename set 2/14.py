
import cryptopals
import base64
import itertools

# ------------------------------------------------------------------------------

_raw = (
	"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG"
	"Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll"
	"cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ"
	"pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.prefix = cryptopals.get_random_key(0, 100)
		self.suffix = base64.standard_b64decode(_raw)

	def encrypt(self, s):
		s = self.prefix + s + self.suffix
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


def get_num_prefix_blocks(block_size):

	"""
	encrypt three blocks of identical bytes to see where the identical cipher
	blocks land (w/ three blocks we should get at least two identical cipher
	blocks). now we know how many blocks the prefix span

	:param block_size:
	:return:
	"""

	test = api.encrypt(3*block_size*'.')
	blocks = list(cryptopals.chunks(test, block_size))

	prev = blocks[0]
	for index, curr in enumerate(blocks[1:]):
		if curr == prev:
			num_prefix_blocks = index
			break
		prev = curr

	return num_prefix_blocks


def find_prefix_padding(num_prefix_blocks, block_size):

	offset = (num_prefix_blocks - 1) * block_size
	prev = '.' * block_size
	for n in range(block_size + 1):
		curr = api.encrypt('.' * n)[offset:offset + block_size]
		if curr == prev:
			break
		prev = curr

	return n - 1


def process_block(pad, prefix, block0, block_index, block_size):

	block0_start = block0 * block_size
	block0_end = block0_start + block_size

	block_start = block_index * block_size
	block_end = block_start + block_size

	plain_text = ''
	for pad_size in xrange(block_size - 1, -1, -1):

		prefix = prefix[1:]

		lookup = {}
		for n in xrange(256):
			s = pad + prefix + chr(n)
			c = api.encrypt(s)[block0_start:block0_end]
			lookup[c] = chr(n)

		c = api.encrypt(pad + '.' * pad_size)[block_start:block_end]
		if c not in lookup:
			break

		found = lookup[c]
		plain_text += found
		prefix += found

	return plain_text

# ------------------------------------------------------------------------------

# find the block size

block_size = get_block_size()

#
# find out the length of the hidden prefix string
#

num_prefix_blocks = get_num_prefix_blocks(block_size)
pad_size = find_prefix_padding(num_prefix_blocks, block_size)
#prefix_length = num_prefix_blocks * block_size - pad_size

num_blocks = len(api.encrypt('')) / block_size

#

pad    = '.' * pad_size			# fill the hidden prefix to a full block
prefix = '.' * block_size

res = []
for block_index in xrange(num_prefix_blocks, num_blocks):
	plain_text = process_block(pad, prefix, num_prefix_blocks, block_index, block_size)
	res.append(plain_text)
	prefix = plain_text

print ''.join(res)

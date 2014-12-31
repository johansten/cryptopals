
from Crypto.Cipher import AES
import string
import math
from itertools import izip, cycle
import os
import struct
import random

#

_english = {
	'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
	'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
	'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
	'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
	'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
	'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
	'y': 0.01974, 'z': 0.00074,

	' ': 0.13,
}

_sum = 0
for w in _english.itervalues():
	_sum += w

_english_log2 = {x: -math.log(y/_sum, 2) for x, y in _english.iteritems()}


def xor_with_single_byte(raw, xor):
	res = ''.join([chr(ord(r) ^ xor) for r in raw])
	return res


def is_printable(x):
	return all(c in string.printable for c in x)

# ------------------------------------------------------------------------------


def find_single_byte_xor(raw):

	min_sum = 65536
	min_xor = -1

	for xor in xrange(256):

		sum = 0
		res = xor_with_single_byte(raw, xor)
		if is_printable(res):

			res = res.lower()
			for r in res:
				sum += _english_log2.get(r, 10)

			if sum < min_sum:
				min_sum = sum
				min_xor = xor

	return min_sum, min_xor

# ------------------------------------------------------------------------------


def hamming_distance(a, b):
	"""	return the hamming distance between strings a and b.
	"""

	sum = 0
	for c, k in izip(a, b):
		n = ord(c) ^ ord(k)
		n = (n & 0x55) + ((n & 0xAA) >> 1)
		n = (n & 0x33) + ((n & 0xCC) >> 2)
		n = (n & 0x0F) + ((n & 0xF0) >> 4)
		sum += n

	return sum


# ------------------------------------------------------------------------------


def xor_strings(raw, key):
	""" return the xor of the two input strings, up to the length of the
		shortest of the two inputs.
	"""
	res = ''.join(chr(ord(r) ^ ord(k)) for r, k in izip(raw, key))
	return res


def xor_repeating_key(raw, key):
	return xor_strings(raw, cycle(key))


def find_repeating_key_xor_length(raw, max_length):

	min_edit_length = 0
	min_edit_sum    = 8

	for key_size in xrange(2, max_length):

		blocks = list(chunks(raw, key_size))
		block0 = blocks[0]

		# sum the edit distances

		edit_sum = 0
		for block in blocks[1:]:
			edit_sum += hamming_distance(block0, block)

		# find the average edit distance over all the processed bytes

		num_bytes = len(raw) - key_size
		edit_sum /= float(num_bytes)

		# lowest?

		if edit_sum < min_edit_sum:
			min_edit_sum    = edit_sum
			min_edit_length = key_size

	return min_edit_length


def find_repeating_key_xor(raw, key_size):
	p = [raw[n::key_size] for n in xrange(key_size)]

	key = []
	for pp in p:
		_, min_xor = find_single_byte_xor(pp)
		key.append(chr(min_xor))
	key = ''.join(key)

	return key

# ------------------------------------------------------------------------------


def pkcs7_pad(s, l):
	""" return a PKCS#7 padded version of the input string, padded to a length a multiple of l
	"""
	r = (l - len(s)) % l
	if r == 0:
		r = l

	return s + r*chr(r)


def remove_pkcs7_padding(s):
	l = ord(s[-1])
	return s[:-l]


def is_valid_pkcs7(s):
	"""
	"""
	l = ord(s[-1])
	if 0 < l < 17:
		return all(ord(s[i]) == l for i in xrange(len(s)-l, len(s)))
	else:
		return False

# ------------------------------------------------------------------------------


def chunks(l, n):
	""" Yield successive n-sized chunks from l.
	"""

	for i in xrange(0, len(l), n):
		yield l[i:i+n]


def encrypt_ebc(s, key):
	cipher = AES.AESCipher(key, AES.MODE_ECB)
	return cipher.encrypt(s)


def decrypt_ebc(s, key):
	cipher = AES.AESCipher(key, AES.MODE_ECB)
	return cipher.decrypt(s)


def encrypt_cbc(raw, key, iv):

	cipher = AES.AESCipher(key, AES.MODE_ECB)

	prev = iv
	res = []

	for chunk in chunks(raw, 16):
		inter = xor_strings(chunk, prev)
		curr = cipher.encrypt(inter)
		res.append(curr)
		prev = curr

	return ''.join(res)


def decrypt_cbc(raw, key, iv):

	cipher = AES.AESCipher(key, AES.MODE_ECB)

	prev_chunk = iv
	res = []

	for chunk in chunks(raw, 16):
		curr = cipher.decrypt(chunk)
		plain = xor_strings(curr, prev_chunk)
		res.append(plain)
		prev_chunk = chunk

	return ''.join(res)


def encrypt_ctr(raw, key, nonce):
	"""
	Encrypt/decrypt the input string, using the provided key and nonce.
	CTR works like rot-13, so encryption/decryption works exactly the same.

	:param raw: plain/cipher text byte string
	:param key: 16 byte encryption key
	:param nonce: 64 bit integer
	:return: AES-CTR encrypted/decryption output, byte string
	"""

	def little_endian_64(x):
		""" convert integer to little endian 8-byte string
		"""
		return struct.pack('<Q', x)

	cipher = AES.AESCipher(key, AES.MODE_ECB)

	counter = 0
	res = []

	nonce_string = little_endian_64(nonce)

	for plain_text in chunks(raw, 16):
		stream = cipher.encrypt(nonce_string + little_endian_64(counter))
		cipher_text = xor_strings(plain_text, stream)
		res.append(cipher_text)
		counter += 1

	return ''.join(res)

# ------------------------------------------------------------------------------


def cbc_padding_oracle_decrypt_block(oracle, c1, c2):

	"""	decrypts c2
	"""

	def padding_inter(inter, n):
		if n == 1:
			return ''
		res = ''.join([chr(i ^ n) for i in inter[-n+1:]])
		return res

	inter = [0] * 16
	plain = [0] * 16

	for index in xrange(1, 17):

		pos = 16 - index

		pre_pad  = get_random_key(pos)
		post_pad = padding_inter(inter, index)

		for n in xrange(256):
			c1prim = pre_pad + chr(n) + post_pad
			if oracle(c1prim + c2):
				i = n ^ index
				inter[pos] = i
				plain[pos] = chr(i ^ ord(c1[pos]))
				break

	return ''.join(plain)


def cbc_padding_oracle_decrypt(oracle, cipher_text, iv):

	# break up in blocks, with IV as block #0

	blocks = [iv] + list(chunks(cipher_text, 16))

	# go through list and decrypt each block

	plain = []
	for n in xrange(len(blocks) - 1):
		p = cbc_padding_oracle_decrypt_block(oracle, *blocks[n:n+2])
		plain.append(p)

	# concatenate plain text results and remove padding

	plain_text = ''.join(plain)
	plain_text = remove_pkcs7_padding(plain_text)
	return plain_text

# ------------------------------------------------------------------------------


def get_random_key(a, b=None):

	if b:
		a = random.randint(a, b)
	return os.urandom(a)


def is_ecb(raw):

	#
	# split file in 16bytes chunks and look for duplicates
	# by storing in a set, and checking the cardinality of the set
	#

	s = {raw[i:i+16] for i in range(0, len(raw), 16)}
	return len(raw) != 16*len(s)

# ------------------------------------------------------------------------------


def to_hex(s):
	return ''.join(x.encode('hex') for x in s)

# ------------------------------------------------------------------------------

class MersenneTwister:

	def __init__(self):
		self.n = 624
		self.m = 397
		self.mt = [0] * self.n
		self.i = 0

	def seed(self, s):

		self.mt[0] = s & 0xffffffff

		prev = self.mt[0]
		for index in xrange(1, self.n):
			t  = prev ^ (prev >> 30)
			t *= 1812433253
			t += index
			t &= 0xffffffff
			self.mt[index] = t
			prev = t

		self.i = self.n

	def rand_int32(self):

		if self.i == self.n:
			self.gen_state()

		y = self.mt[self.i]
		self.i += 1

		# temper output
		y ^= (y >> 11)
		y ^= (y <<  7) & 0x9d2c5680
		y ^= (y << 15) & 0xefc60000
		y ^= (y >> 18)
		return y

	def gen_state(self):

		MATRIX_A   = 0x9908b0df
		UPPER_MASK = 0x80000000
		LOWER_MASK = 0x7fffffff

		lut = [0, MATRIX_A]

		for k in xrange(0, self.n - self.m):
			y = (self.mt[k] & UPPER_MASK) | (self.mt[k+1] & LOWER_MASK)
			self.mt[k] = self.mt[k + self.m] ^ (y >> 1) ^ lut[y & 1]

		for k in xrange(self.n - self.m, self.n - 1):
			y = (self.mt[k] & UPPER_MASK) | (self.mt[k+1] & LOWER_MASK)
			self.mt[k] = self.mt[k + (self.m - self.n)] ^ (y >> 1) ^ lut[y & 1]

		y = (self.mt[self.n - 1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK)
		self.mt[self.n - 1] = self.mt[self.m - 1] ^ (y >> 1) ^ lut[y & 1]

		self.i = 0


def mt_untemper(y):

	# untemper stage 4
	y = y ^ (y >> 18)

	# untemper stage 3
	y = y ^ (y << 15) & 0xefc60000

	# untemper stage 2
	a = y ^ (y << 7) & 0x9d2c5680
	b = y ^ (a << 7) & 0x9d2c5680
	c = y ^ (b << 7) & 0x9d2c5680
	d = y ^ (c << 7) & 0x9d2c5680
	y = y ^ (d << 7) & 0x9d2c5680

	# untemper stage 1
	a = y ^ (y >> 11)
	y = y ^ (a >> 11)

	return y

# ------------------------------------------------------------------------------


class Digest(object):

	def update_state(self, state):

		for i, s in enumerate(state):
			self.state[i] += s
			self.state[i] &= 0xffffffff

	def update(self, data):

		size = len(data)
		offset = 0

		left = self.total & 0x3f
		fill = 64 - left

		self.total += size

		if (left != 0) & (size >= fill):
			self.buffer = self.buffer[:left] + data[:fill]
			self.process(self.buffer)
			offset += fill
			size   -= fill
			left = 0

		while size >= 64:
			self.process(data[offset:offset+64])
			offset += 64
			size   -= 64

		if size > 0:
			self.buffer = self.buffer[:left] + data[offset:]

	def finish(self):
		padding = self.get_padding(self.total)
		self.update(padding)
		return self.state_to_bytes()

# ------------------------------------------------------------------------------

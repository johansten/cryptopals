
import cryptopals
import struct


# ------------------------------------------------------------------------------

class MD4(cryptopals.Digest):

	state0 = (
		"\x01\x23\x45\x67"
		"\x89\xab\xcd\xef"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
	)

	def __init__(self, state=state0, length=0):

		self.total = length
		self.state = read_little_endian_int32s(state)
		self.buffer = '0' * 64

	def process(self, data):

		x = read_little_endian_int32s(data)

		a, b, c, d = self.state
		a = f1(a, b, c, d,  0,  3, x)
		d = f1(d, a, b, c,  1,  7, x)
		c = f1(c, d, a, b,  2, 11, x)
		b = f1(b, c, d, a,  3, 19, x)
		a = f1(a, b, c, d,  4,  3, x)
		d = f1(d, a, b, c,  5,  7, x)
		c = f1(c, d, a, b,  6, 11, x)
		b = f1(b, c, d, a,  7, 19, x)
		a = f1(a, b, c, d,  8,  3, x)
		d = f1(d, a, b, c,  9,  7, x)
		c = f1(c, d, a, b, 10, 11, x)
		b = f1(b, c, d, a, 11, 19, x)
		a = f1(a, b, c, d, 12,  3, x)
		d = f1(d, a, b, c, 13,  7, x)
		c = f1(c, d, a, b, 14, 11, x)
		b = f1(b, c, d, a, 15, 19, x)

		a = f2(a, b, c, d,  0,  3, x)
		d = f2(d, a, b, c,  4,  5, x)
		c = f2(c, d, a, b,  8,  9, x)
		b = f2(b, c, d, a, 12, 13, x)
		a = f2(a, b, c, d,  1,  3, x)
		d = f2(d, a, b, c,  5,  5, x)
		c = f2(c, d, a, b,  9,  9, x)
		b = f2(b, c, d, a, 13, 13, x)
		a = f2(a, b, c, d,  2,  3, x)
		d = f2(d, a, b, c,  6,  5, x)
		c = f2(c, d, a, b, 10,  9, x)
		b = f2(b, c, d, a, 14, 13, x)
		a = f2(a, b, c, d,  3,  3, x)
		d = f2(d, a, b, c,  7,  5, x)
		c = f2(c, d, a, b, 11,  9, x)
		b = f2(b, c, d, a, 15, 13, x)

		a = f3(a, b, c, d,  0,  3, x)
		d = f3(d, a, b, c,  8,  9, x)
		c = f3(c, d, a, b,  4, 11, x)
		b = f3(b, c, d, a, 12, 15, x)
		a = f3(a, b, c, d,  2,  3, x)
		d = f3(d, a, b, c, 10,  9, x)
		c = f3(c, d, a, b,  6, 11, x)
		b = f3(b, c, d, a, 14, 15, x)
		a = f3(a, b, c, d,  1,  3, x)
		d = f3(d, a, b, c,  9,  9, x)
		c = f3(c, d, a, b,  5, 11, x)
		b = f3(b, c, d, a, 13, 15, x)
		a = f3(a, b, c, d,  3,  3, x)
		d = f3(d, a, b, c, 11,  9, x)
		c = f3(c, d, a, b,  7, 11, x)
		b = f3(b, c, d, a, 15, 15, x)

		self.update_state([a, b, c, d])

	@staticmethod
	def get_padding(length):
		last = length & 0x3F
		pad_size = 56 - last if last < 56 else 120 - last
		msg_pad = '\x80' + '\0' * (pad_size - 1)
		msg_len = struct.pack('<Q', length << 3)
		return msg_pad + msg_len

	def state_to_bytes(self):
		return write_little_endian_int32s(self.state)


# ------------------------------------------------------------------------------

def read_little_endian_int32s(data):
	res = [struct.unpack('<L', b)[0] for b in cryptopals.chunks(data, 4)]
	return res


def write_little_endian_int32s(data):
	res = [struct.pack('<L', n) for n in data]
	return ''.join(res)


# ------------------------------------------------------------------------------

def rol(x, n):
	""" rotate left
	"""
	return ((x << n) & 0xffffffff) | ((x & 0xffffffff) >> (32 - n))


def F(x, y, z):
	return x & y | ~x & z


def G(x, y, z):
	return x & y | x & z | y & z


def H(x, y, z):
	return x ^ y ^ z


def f1(a, b, c, d, k, s, X):
	return rol(a + F(b, c, d) + X[k], s)


def f2(a, b, c, d, k, s, X):
	return rol(a + G(b, c, d) + X[k] + 0x5a827999, s)


def f3(a, b, c, d, k, s, X):
	return rol(a + H(b, c, d) + X[k] + 0x6ed9eba1, s)

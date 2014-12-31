
import cryptopals
import struct


# ------------------------------------------------------------------------------


class SHA1(cryptopals.Digest):

	state0 = (
		"\x67\x45\x23\x01"
		"\xef\xcd\xab\x89"
		"\x98\xba\xdc\xfe"
		"\x10\x32\x54\x76"
		"\xc3\xd2\xe1\xf0"
	)

	def __init__(self, state=state0, length=0):

		self.state = read_big_endian_int32s(state)
		self.total = length
		self.buffer = '0' * 64

	def process(self, data):

		w = [0] * 80
		w[:16] = read_big_endian_int32s(data)
		for n in xrange(16, 80):
			w[n] = rol(w[n-3] ^ w[n-8] ^ w[n-14] ^ w[n-16], 1)

		def chunk(a, b, c, d, e, n, f, k):
			for i in xrange(n, n + 20):
				a, b, c, d, e = (
					(rol(a, 5) + f(b, c, d) + e + k + w[i]) & 0xffffffff,
					a,
					rol(b, 30),
					c,
					d
				)
			return (a, b, c, d, e)

		a, b, c, d, e = self.state

		a, b, c, d, e = chunk(a, b, c, d, e,  0, f0, k0)
		a, b, c, d, e = chunk(a, b, c, d, e, 20, f1, k1)
		a, b, c, d, e = chunk(a, b, c, d, e, 40, f2, k2)
		a, b, c, d, e = chunk(a, b, c, d, e, 60, f1, k3)

		self.update_state([a, b, c, d, e])

	@staticmethod
	def get_padding(length):
		last = length & 0x3F
		pad_size = 56 - last if last < 56 else 120 - last
		msg_pad = '\x80' + '\0' * (pad_size - 1)
		msg_len = struct.pack('>Q', length << 3)
		return msg_pad + msg_len

	def state_to_bytes(self):
		return write_big_endian_int32s(self.state)

# ------------------------------------------------------------------------------


def read_big_endian_int32s(data):
	res = [struct.unpack('>L', b)[0] for b in cryptopals.chunks(data, 4)]
	return res


def write_big_endian_int32s(data):
	res = [struct.pack('>L', n) for n in data]
	return ''.join(res)

# ------------------------------------------------------------------------------


def rol(x, n):
	""" rotate left
	"""
	return ((x << n) | (x >> (32 - n))) & 0xffffffff


def f0(x, y, z):
	return z ^ (x & (y ^ z))


def f1(x, y, z):
	return x ^ y ^ z


def f2(x, y, z):
	return (x & y) | (z & (x | y))

k0 = 0x5A827999
k1 = 0x6ED9EBA1
k2 = 0x8F1BBCDC
k3 = 0xCA62C1D6

# ------------------------------------------------------------------------------

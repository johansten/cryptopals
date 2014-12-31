
import cryptopals
import cryptopals.md4


class KeyedMD4Mac:

	def __init__(self):
		self.key = cryptopals.get_random_key(1, 20)

	def sign(self, message):
		self.md4 = cryptopals.md4.MD4()
		self.md4.update(self.key + message)
		return self.md4.finish()

	def is_valid(self, message, mac):
		return self.sign(message) == mac


message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

keyed_md4 = KeyedMD4Mac()
mac0      = keyed_md4.sign(message)

suffix = ";admin=true"

# try different key sizes until we find a match

for n in xrange(32):

	#

	glue   = cryptopals.md4.MD4.get_padding(len(message) + n)
	length = n + len(message) + len(glue)
	s = cryptopals.md4.MD4(mac0, length)
	s.update(suffix)
	mac = s.finish()

	# check with our oracle function

	if keyed_md4.is_valid(message + glue + suffix, mac):
		print n
		break

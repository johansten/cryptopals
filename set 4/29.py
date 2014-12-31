
import cryptopals
import cryptopals.sha1


class KeyedSHA1Mac:

	def __init__(self):
		self.key = cryptopals.get_random_key(1, 20)

	def sign(self, message):
		self.sha = cryptopals.sha1.SHA1()
		self.sha.update(self.key + message)
		return self.sha.finish()

	def is_valid(self, message, mac):
		return self.sign(message) == mac


message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

keyed_sha = KeyedSHA1Mac()
mac0      = keyed_sha.sign(message)

suffix = ";admin=true"

# try different key sizes until we find a match

for n in xrange(32):

	#

	glue   = cryptopals.sha1.SHA1.get_padding(len(message) + n)
	length = n + len(message) + len(glue)
	s = cryptopals.sha1.SHA1(mac0, length)
	s.update(suffix)
	mac = s.finish()

	# check with our oracle function

	if keyed_sha.is_valid(message + glue + suffix, mac):
		print n
		break


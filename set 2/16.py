
import cryptopals


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.iv  = cryptopals.get_random_key(16)

	def encrypt_string(self, s):

		raw = ("comment1=cooking%20MCs;userdata=" +
			  s + ";comment2=%20like%20a%20pound%20of%20bacon")
		raw = cryptopals.pkcs7_pad(raw, 16)
		c = cryptopals.encrypt_cbc(raw, self.key, self.iv)
		return c

	def is_admin(self, s):
		p = cryptopals.decrypt_cbc(s, self.key, self.iv)
		return ';admin=true;' in p

#
# Isolate ";admin-true" in it's own block, w/ a whole block of padding in front of it.
#
# Change '-' to '=' by flipping a bit in the cipher output.
# This will scramble the previous block, but that's padding anyway.
# Just need to check that none of the scrambled data messes up the parsing later on
#

userdata = "----------------;admin-true"

raw = ("comment1=cooking%20MCs;userdata=" +
	  userdata + ";comment2=%20like%20a%20pound%20of%20bacon")
print list(cryptopals.chunks(raw, 16))

#

api = Api()
cipher_text = api.encrypt_string(userdata)

# the position of the byte we need to modify
pos = 2 * 16 + 6

modification = chr(ord(cipher_text[pos]) ^ 16)
cipher_text = cipher_text[:pos] + modification + cipher_text[pos+1:]

print api.is_admin(cipher_text)

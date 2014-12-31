
import cryptopals


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.nonce = 0

	def encrypt_string(self, s):

		raw = ("comment1=cooking%20MCs;userdata=" +
			  s + ";comment2=%20like%20a%20pound%20of%20bacon")
		raw = cryptopals.pkcs7_pad(raw, 16)
		c = cryptopals.encrypt_ctr(raw, self.key, self.nonce)
		return c

	def is_admin(self, s):
		p = cryptopals.encrypt_ctr(s, self.key, self.nonce)
		return ';admin=true;' in p


#
# Change '-' to '=' by flipping a bit in the cipher output.
#

userdata = "x;admin-true"

raw = ("comment1=cooking%20MCs;userdata=" +
	  userdata + ";comment2=%20like%20a%20pound%20of%20bacon")
print list(cryptopals.chunks(raw, 16))


api = Api()
cipher_text = api.encrypt_string(userdata)

# the position of the byte we need to modify
# NB: in CTR we just modify the byte directly, instead of modifying
# the previous block like in CBC mode.

pos = 2 * 16 + 7

modification = chr(ord(cipher_text[pos]) ^ 16)
cipher_text = cipher_text[:pos] + modification + cipher_text[pos+1:]

print api.is_admin(cipher_text)

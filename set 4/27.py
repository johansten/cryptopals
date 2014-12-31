
import cryptopals


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.iv  = self.key

	def encrypt(self, s):

		raw = ("comment1=cooking%20MCs;userdata=" +
			  s + ";comment2=%20like%20a%20pound%20of%20bacon")
		raw = cryptopals.pkcs7_pad(raw, 16)
		c = cryptopals.encrypt_cbc(raw, self.key, self.iv)
		return c

	def decrypt(self, cipher_text):
		return cryptopals.decrypt_cbc(cipher_text, self.key, self.iv)

	def is_admin(self, s):
		p = cryptopals.decrypt_cbc(s, self.key, self.iv)
		return ';admin=true;' in p

api = Api()

# get encrypted string
cipher_text = api.encrypt("test")

# doctor the cipher text
block0 = cipher_text[:16]
cipher_text = block0 + '\0'*16 + block0

# server will decrypt and return plain text as error message if non-ASCII data
plain_text = api.decrypt(cipher_text)

# retrieve the key by xor:ing block #0 and #2
key = cryptopals.xor_repeating_key(plain_text[0:16], plain_text[32:48])

# encrypt the data we want to send

user_data = "test;admin=true"
raw = (
	"comment1=cooking%20MCs;userdata=" +
	user_data +
	";comment2=%20like%20a%20pound%20of%20bacon"
)

raw = cryptopals.pkcs7_pad(raw, 16)
cipher_text = cryptopals.encrypt_cbc(raw, key, key)

# success??
print api.is_admin(cipher_text)

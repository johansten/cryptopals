
import cryptopals
import base64


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.nonce = 0

	def encrypt(self, plain_text):
		cipher_text = cryptopals.encrypt_ctr(plain_text, self.key, self.nonce)
		return cipher_text

	def edit(self, cipher_text, offset, new_text):
		plain_text  = self.encrypt(cipher_text)
		edited_text = plain_text[:offset] + new_text + plain_text[offset + len(new_text):]
		cipher_text = self.encrypt(edited_text)
		return cipher_text

f = open("25.txt", "rb")
base64_text = f.read()
f.close()

cipher_text = base64.standard_b64decode(base64_text)
plain_text  = cryptopals.decrypt_ebc(cipher_text, "YELLOW SUBMARINE")

api = Api()
cipher_text = api.encrypt(plain_text)

length = len(cipher_text)
edit_text = '\0' * length
key_stream = api.edit(cipher_text, 0, edit_text)

plain_text = cryptopals.xor_repeating_key(cipher_text, key_stream)
print plain_text


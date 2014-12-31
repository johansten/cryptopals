
import cryptopals
import base64


input_strings = [
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)
		self.iv  = cryptopals.get_random_key(16)

	def encrypt(self, base64_text):
		plain_text  = base64.standard_b64decode(base64_text)
		plain_text  = cryptopals.pkcs7_pad(plain_text, 16)
		cipher_text = cryptopals.encrypt_cbc(plain_text, self.key, self.iv)
		return cipher_text, self.iv

	def cbc_padding_oracle(self, cipher_text):
		p = cryptopals.decrypt_cbc(cipher_text, self.key, self.iv)
		return cryptopals.is_valid_pkcs7(p)

api = Api()

for line in input_strings:
	cipher_text, iv = api.encrypt(line)
	print cryptopals.cbc_padding_oracle_decrypt(
		api.cbc_padding_oracle, cipher_text, iv
	)


import cryptopals
import base64


with open("6.txt", "rb") as f:

	base64_text = f.read()
	cipher_text = base64.standard_b64decode(base64_text)

	key_size = cryptopals.find_repeating_key_xor_length(cipher_text, 42)
	key = cryptopals.find_repeating_key_xor(cipher_text, key_size)
	print cryptopals.xor_repeating_key(cipher_text, key)

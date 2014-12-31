
import cryptopals
import base64
from collections import Counter


with open("20.txt", "rb") as f:
	# encrypt plain texts

	key = cryptopals.get_random_key(16)

	cipher_texts = [
		cryptopals.encrypt_ctr(
			base64.standard_b64decode(line),
			key,
			0
		)
		for line in f.readlines()
	]

	# count the cipher text lengths, and create a sorted list of length
	# to be used as segment end points

	c = Counter(map(len, cipher_texts))
	segments = [0] + sorted(c)

	xor_key = ""
	for n in xrange(len(segments) - 1):

		# for each segment, concatenate the cipher text parts

		start = segments[n]
		end   = segments[n+1]

		concat = ''.join((c[start:end] for c in cipher_texts))

		# now it's been transformed into a classic vigenere cipher form
		# so we just find the repeating key

		segment_length = end - start
		xor_key_segment = cryptopals.find_repeating_key_xor(concat, segment_length)

		# add segment key to global key

		xor_key += xor_key_segment

	for cipher_text in cipher_texts:
		plain_text = cryptopals.xor_repeating_key(cipher_text, xor_key)
		print plain_text

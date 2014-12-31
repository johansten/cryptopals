
import cryptopals
import cryptopals.sha1

BLOCK_LENGTH = 64


def hmac_digest(key, message, digest):

	ipad = '\x36' * BLOCK_LENGTH
	opad = '\x5c' * BLOCK_LENGTH

	if len(key) > BLOCK_LENGTH:
		key = key[:BLOCK_LENGTH]
	else:
		key = key + '\0' * (BLOCK_LENGTH - len(key))

	ipad = cryptopals.xor_repeating_key(ipad, key)
	opad = cryptopals.xor_repeating_key(opad, key)

	inner = digest()
	inner.update(ipad)
	inner.update(message)

	outer = digest()
	outer.update(opad)
	outer.update(inner.finish())
	return outer.finish()


def hmac_sha1(key, message):
	return hmac_digest(key, message, cryptopals.sha1.SHA1)

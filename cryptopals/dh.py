
import random


p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2


def generate_privkey(p):
	a = random.getrandbits(1536)
	if a > p:
		a -= p
	return a


def get_pubkey(priv, g, p):
	return pow(g, priv, p)


def get_dh_key(a_pub, b_priv, p):
	s = pow(a_pub, b_priv, p)
	session = _long_to_bytes(s)
	return session


def _long_to_bytes(l):

	# convert to hex string first, then each hex 2-tuple to a byte

	h = hex(l)[2:]
	if h[-1] == 'L':
		h = h[:-1]
	if len(h) & 1 == 1:
		h = '0%s' % h
	return h.decode('hex')

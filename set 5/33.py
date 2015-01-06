
import cryptopals
import cryptopals.dh as dh
import cryptopals.sha1


def get_key(a_pub, b_priv, p):
	session = dh.get_dh_key(a_pub, b_priv, p)
	sha1 = cryptopals.sha1.SHA1()
	sha1.update(session)
	return sha1.finish()


a_priv = dh.generate_privkey(dh.p)
a_pub  = dh.get_pubkey(a_priv, dh.g, dh.p)

b_priv = dh.generate_privkey(dh.p)
b_pub  = dh.get_pubkey(b_priv, dh.g, dh.p)

print cryptopals.to_hex(get_key(b_pub, a_priv, dh.p))
print cryptopals.to_hex(get_key(a_pub, b_priv, dh.p))
print cryptopals.to_hex(get_key(dh.p, b_priv, dh.p))

s = pow(dh.p, b_priv, dh.p)
print s


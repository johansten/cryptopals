

import cryptopals
import cryptopals.dh as dh
import cryptopals.sha1

import simplejson as json
import threading
import Queue
import base64


def get_aes_key(a_pub, b_priv, p):
	session = dh.get_dh_key(a_pub, b_priv, p)
	sha1 = cryptopals.sha1.SHA1()
	sha1.update(session)
	return sha1.finish()[0:16]


def get_null_key():
	sha1 = cryptopals.sha1.SHA1()
	sha1.update('\0')
	return sha1.finish()[0:16]


class Actor(object):

	def __init__(self):
		self.q = Queue.Queue()

	def recv(self):
		msg = self.q.get()
		return json.loads(msg)

	def send(self, actor, msg):
		actor.q.put(json.dumps(msg))


class ClientA(Actor):

	def __init__(self):
		super(ClientA, self).__init__()

	def start(self, b):

		p = dh.p
		g = dh.g

		priv = dh.generate_privkey(p)
		pub  = dh.get_pubkey(priv, g, p)

	#	A->B: send p, g, A

		self.send(b, {'p':p, 'g':g, 'pub_key':pub})

	#	B->A: send B

		res = self.recv()
		b_pub = res['pub_key']

	#	A->B: send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv

		msg = "Ice ice baby!"
		key = get_aes_key(b_pub, priv, p)
		iv  = cryptopals.get_random_key(16)

		msg = cryptopals.pkcs7_pad(msg, 16)
		cipher_text = cryptopals.encrypt_cbc(msg, key, iv) + iv
		base64_text = base64.standard_b64encode(cipher_text)
		self.send(b, {'cipher_text':base64_text})

	#	B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

		res = self.recv()
		base64_text = res['cipher_text']
		cipher_text = base64.standard_b64decode(base64_text)

		iv = cipher_text[-16:]
		cipher = cipher_text[:-16]
		msg = cryptopals.decrypt_cbc(cipher, key, iv)

		print "A: %s" % msg

class ClientB(Actor):

	def __init__(self):
		super(ClientB, self).__init__()

	def start(self, a):

	#	A->B: send p, g, A

		res = self.recv()
		p = res['p']
		g = res['g']
		a_pub = res['pub_key']

		priv = dh.generate_privkey(p)
		pub  = dh.get_pubkey(priv, g, p)

	#	B->A: send B

		self.send(a, {'pub_key':pub})

		key = get_aes_key(a_pub, priv, p)

	#	A->B: send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv

		res = self.recv()
		base64_text = res['cipher_text']
		cipher_text = base64.standard_b64decode(base64_text)

		iv = cipher_text[-16:]
		cipher = cipher_text[:-16]
		msg = cryptopals.decrypt_cbc(cipher, key, iv)

	#	B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

		iv  = cryptopals.get_random_key(16)
		cipher_text = cryptopals.encrypt_cbc(msg, key, iv) + iv
		base64_text = base64.standard_b64encode(cipher_text)

		self.send(a, {'cipher_text':base64_text})

class ClientM(Actor):

	def __init__(self):
		super(ClientM, self).__init__()

	def start(self, a, b):

	#	A->M: send p, g, A

		res = self.recv()
		p = res['p']
		g = res['g']

	#	M->B: send "p", "g", "p"
	#	B->M: send "B"
	#	M->A: send "p"

		self.send(b, {'p':p, 'g':g, 'pub_key':p})
		res = self.recv()
		self.send(a, {'pub_key':p})

	#	A->M: send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	#	M->B: relay that to B

		res = self.recv()
		self.send(b, res)

	#	decrypt message

		base64_text = res['cipher_text']
		cipher_text = base64.standard_b64decode(base64_text)

		key = get_null_key()
		iv = cipher_text[-16:]
		cipher = cipher_text[:-16]
		msg = cryptopals.decrypt_cbc(cipher, key, iv)
		print "M: %s" % msg

	#	B->M: send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
	#	M->A: relay that to A

		res = self.recv()
		self.send(a, res)

a = ClientA()
b = ClientB()
m = ClientM()

if True:
	threading.Thread(target = a.start, args = (m,)).start()
	threading.Thread(target = b.start, args = (m,)).start()
	threading.Thread(target = m.start, args = (a,b)).start()
else:
	threading.Thread(target = a.start, args = (b,)).start()
	threading.Thread(target = b.start, args = (a,)).start()

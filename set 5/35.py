
import cryptopals
import cryptopals.dh as dh
import cryptopals.sha1
import base64

import simplejson as json
import threading
import Queue


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

	def __init__(self, id):
		self.q = Queue.Queue()
		self.id = id

	def recv(self):
		msg = self.q.get()
		return json.loads(msg)

	def send(self, dest, msg):
		msg['src'] = self.id
		dest.q.put(json.dumps(msg))


class ClientA(Actor):

	def __init__(self, id):
		super(ClientA, self).__init__(id)

	def negotiate_group(self, dest):

		self.send(dest, {'type':'NEG', 'p':dh.p, 'g':dh.g})

		res = self.recv()
		p = res['p']
		g = res['g']

		priv = dh.generate_privkey(p)
		pub  = dh.get_pubkey(priv, g, p)
		self.send(dest, {'type':'PUB', 'key':pub})

		res = self.recv()
		b_pub = res['key']
		self.key = get_aes_key(b_pub, priv, p)

	def send_msg(self, dest, msg):

		iv  = cryptopals.get_random_key(16)
		msg = cryptopals.pkcs7_pad(msg, 16)
		cipher_text = cryptopals.encrypt_cbc(msg, self.key, iv) + iv
		base64_text = base64.standard_b64encode(cipher_text)
		self.send(dest, {'type':'MSG', 'cipher_text':base64_text})
		print "A sent: %s" % msg

		res = self.recv()
		base64_text = res['cipher_text']
		cipher_text = base64.standard_b64decode(base64_text)

		iv = cipher_text[-16:]
		cipher = cipher_text[:-16]
		msg = cryptopals.decrypt_cbc(cipher, self.key, iv)
		print "A recvd: %s" % msg

	def close(self, dest):
		self.send(dest, {'type':'END'})


class ClientB(Actor):

	def __init__(self, id):
		super(ClientB, self).__init__(id)

	def wait(self, dest):
		t = threading.Thread(target = self.start, args = (dest,))
		t.start()

	def start(self, dest):

		while True:
			res = self.recv()
			t = res['type']

			if t == 'NEG':
				p = res['p']
				g = res['g']
				self.send(dest, {'type':'ACK', 'p':p, 'g':g})

			if t == 'PUB':
				a_pub = res['key']
				priv = dh.generate_privkey(p)
				pub  = dh.get_pubkey(priv, g, p)

				self.key = get_aes_key(a_pub, priv, p)
				self.send(dest, {'type':'PUB', 'key':pub})

			if t == 'MSG':

				base64_text = res['cipher_text']
				cipher_text = base64.standard_b64decode(base64_text)

				iv = cipher_text[-16:]
				cipher = cipher_text[:-16]
				msg = cryptopals.decrypt_cbc(cipher, self.key, iv)

				iv  = cryptopals.get_random_key(16)
				cipher_text = cryptopals.encrypt_cbc(msg, self.key, iv) + iv
				base64_text = base64.standard_b64encode(cipher_text)

				self.send(dest, {'type':'MSG', 'cipher_text':base64_text})

			if t == 'END':
				break


class ClientM1(Actor):

	def __init__(self, id):
		super(ClientM1, self).__init__(id)

	def wait(self, a, b):
		t = threading.Thread(target = self.start, args = (a, b,))
		t.start()

	def start(self, a, b):

		sha1 = cryptopals.sha1.SHA1()
		sha1.update('\1')
		self.key = sha1.finish()[0:16]

		while True:
			res = self.recv()
			dest = a if res['src'] != 'A' else b

			t = res['type']
			if t == 'NEG' or t == 'ACK':
				res['g'] = 1

			if t == 'MSG':
				base64_text = res['cipher_text']
				cipher_text = base64.standard_b64decode(base64_text)

				iv = cipher_text[-16:]
				cipher = cipher_text[:-16]
				msg = cryptopals.decrypt_cbc(cipher, self.key, iv)
				print "M:", msg

			self.send(dest, res)
			if t == 'END':
				break


class ClientM2(Actor):

	def __init__(self, id):
		super(ClientM2, self).__init__(id)

	def wait(self, a, b):
		t = threading.Thread(target = self.start, args = (a, b,))
		t.start()

	def start(self, a, b):

		sha1 = cryptopals.sha1.SHA1()
		sha1.update('\0')
		self.key = sha1.finish()[0:16]

		while True:
			res = self.recv()
			dest = a if res['src'] != 'A' else b

			t = res['type']
			if t == 'NEG' or t == 'ACK':
				res['g'] = res['p']

			if t == 'MSG':
				base64_text = res['cipher_text']
				cipher_text = base64.standard_b64decode(base64_text)

				iv = cipher_text[-16:]
				cipher = cipher_text[:-16]
				msg = cryptopals.decrypt_cbc(cipher, self.key, iv)
				print "M:", msg

			self.send(dest, res)
			if t == 'END':
				break


class ClientM3(Actor):

	def __init__(self, id):
		super(ClientM3, self).__init__(id)

	def wait(self, a, b):
		t = threading.Thread(target = self.start, args = (a, b,))
		t.start()

	def start(self, a, b):

		sha1 = cryptopals.sha1.SHA1()
		sha1.update('\1')
		key_0 = sha1.finish()[0:16]

		while True:
			res = self.recv()
			dest = a if res['src'] != 'A' else b

			t = res['type']
			if t == 'NEG' or t == 'ACK':
				res['g'] = res['p'] - 1
				key_1 = get_aes_key(res['g'], 1, res['p'])

			if t == 'MSG':
				base64_text = res['cipher_text']
				cipher_text = base64.standard_b64decode(base64_text)

				iv = cipher_text[-16:]
				cipher = cipher_text[:-16]
				msg = cryptopals.decrypt_cbc(cipher, key_0, iv)
				if not cryptopals.is_valid_pkcs7(msg):
					msg = cryptopals.decrypt_cbc(cipher, key_1, iv)
				print "M:", msg

			self.send(dest, res)
			if t == 'END':
				break

# ------------------------------------------------------------------------------


def run_attack(mitm):

	a = ClientA('A')
	b = ClientB('B')

	b.wait(mitm)
	mitm.wait(a, b)

	a.negotiate_group(mitm)
	a.send_msg(mitm, "Ice Ice Baby!")
	a.close(mitm)
	print "-------"

run_attack(ClientM1('M'))
run_attack(ClientM2('M'))
run_attack(ClientM3('M'))

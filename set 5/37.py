import cryptopals
import cryptopals.dh as dh
import cryptopals.hmac
import cryptopals.sha256

import threading
import Queue


def sha256(x):
	m = cryptopals.sha256.SHA256()
	m.update(x)
	return m.finish()


def get_u(a, b):
	mac = sha256(str(a) + str(b))
	u = int(cryptopals.to_hex(mac), 16)
	return u

# ------------------------------------------------------------------------------

#	these params could be negotiated just like in DH

n = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

# ------------------------------------------------------------------------------

#	these would go in a db, with password hashed

email = "johan.sten@gmail.com"
password = "YELLOW SUBMARINE"

# ------------------------------------------------------------------------------


class Actor(object):

	def __init__(self):
		self.q = Queue.Queue()

	def recv(self):
		return self.q.get()

	def send(self, dest, msg):
		dest.q.put(msg)


class Client(Actor):

	def __init__(self):
		super(Client, self).__init__()

	def login(self, dest, email, password):

	#	send email, a_pub

		a_priv = dh.generate_privkey(n)
		a_pub  = dh.get_pubkey(a_priv, g, n)
		self.send(dest, {'email': email, 'pub': a_pub})

	#	recv salt, b_pub

		res = self.recv()
		salt  = res['salt']
		b_pub = res['pub']

	#	send hmac

		u = get_u(a_pub, b_pub)

		mac = sha256(salt + password)
		x = int(cryptopals.to_hex(mac), 16)

		s = pow(
			(b_pub - k * pow(g, x, n)),
			(a_priv + u * x),
			n
		)

		key = sha256(str(s))
		hmac = cryptopals.hmac.hmac_sha256(key, salt)
		self.send(dest, {'hmac': hmac})

	#	recv login status

		res = self.recv()
		return res['success']


class Client1(Actor):

#	Client 1 sets 'a_pub' to '0', which in turn
#	makes 'S' on the server become '0' as well
#		s = pow(
#			a_pub * pow(v, u, n),
#			b_priv,
#			n
#		)
#
#	so we need to set S on the client to zero
#	for the hmac's to match

	def __init__(self):
		super(Client1, self).__init__()

	def login(self, dest, email):

	#	send email, a_pub

		self.send(dest, {'email': email, 'pub': 0})

	#	recv salt, b_pub

		res = self.recv()
		salt  = res['salt']
		b_pub = res['pub']

	#	send hmac

		s = 0
		key = sha256(str(s))
		hmac = cryptopals.hmac.hmac_sha256(key, salt)
		self.send(dest, {'hmac': hmac})

	#	recv login status

		res = self.recv()
		return res['success']


class Client2(Actor):

#	Client 2 sets 'a_pub' to a multiple of 'n',
#	which in turn makes 'S' on the server become '0'
#		s = pow(
#			a_pub * pow(v, u, n),
#			b_priv,
#			n
#		)
#
#	so we need to set S on the client to zero
#	for the hmac's to match

	def __init__(self):
		super(Client2, self).__init__()

	def login(self, dest, email):

	#	send email, a_pub

		self.send(dest, {'email': email, 'pub': n*3})

	#	recv salt, b_pub

		res = self.recv()
		salt  = res['salt']
		b_pub = res['pub']

	#	send hmac

		s = 0
		key = sha256(str(s))
		hmac = cryptopals.hmac.hmac_sha256(key, salt)
		self.send(dest, {'hmac': hmac})

	#	recv login status

		res = self.recv()
		return res['success']


class Server(Actor):

	def __init__(self):
		super(Server, self).__init__()

	def wait(self, dest):
		t = threading.Thread(target = self.run, args = (dest,))
		t.start()

	def run(self, dest):

	#	recv email, a_pub

		res = self.recv()
	#	email = res['email']	#	use email to look up password in db
		a_pub = res['pub']

	#	send salt, b_pub

		salt = cryptopals.get_random_key(16)
		mac = sha256(salt + password)
		x = int(cryptopals.to_hex(mac), 16)
		v = pow(g, x, n)

		b_priv = dh.generate_privkey(n)
		b_pub  = pow(g, b_priv, n)
		b_pub += k*v
		self.send(dest, {'salt': salt, 'pub': b_pub})

	#	recv hmac

		res = self.recv()
		hmac0 = res['hmac']

	#	send login status

		u = get_u(a_pub, b_pub)

		#	S:

		s = pow(
			a_pub * pow(v, u, n),
			b_priv,
			n
		)

		key = sha256(str(s))
		hmac = cryptopals.hmac.hmac_sha256(key, salt)
		success = (hmac == hmac0)
		self.send(dest, {'success': success})


# ------------------------------------------------------------------------------

def case1():
	a = Client1()
	b = Server()

	b.wait(a)
	print a.login(b, email)


def case2():
	a = Client2()
	b = Server()

	b.wait(a)
	print a.login(b, email)


case1()
case2()

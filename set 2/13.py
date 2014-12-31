
import cryptopals
import urlparse


def get_profile_string(user):
	return "email=%s&uid=10&role=user" % user


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)

	def encrypt_profile(self, user):
		profile = get_profile_string(user)
		profile = cryptopals.pkcs7_pad(profile, 16)
		cipher  = cryptopals.encrypt_ebc(profile, self.key)
		return cipher

	def decrypt_profile(self, p):
		s = cryptopals.decrypt_ebc(p, self.key)
		s = cryptopals.remove_pkcs7_padding(s)
		return urlparse.parse_qs(s)


api = Api()

#
# isolate "admin" + padding in its own block
# ["admin..........."]

user = "..........admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
admin = api.encrypt_profile(user)[16:32]

#
# set a username so that "role=" ends a block
# ["email=johan@foo.", "com&uid=10&role="]
#

user = "johan@foo.com"
prefix = api.encrypt_profile(user)[:32]

#
#	concatenate our wanted blocks and check result
# ["email=johan@foo.", "com&uid=10&role=", "admin..........."]
#

print api.decrypt_profile(prefix + admin)

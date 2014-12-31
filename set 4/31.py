
import cryptopals
import cryptopals.hmac
import time


# ------------------------------------------------------------------------------

def _insecure_compare(s1, s2):

	for n in xrange(len(s1)):
		if s1[n] != s2[n]:
			return False
		time.sleep(0.050)

	return True


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)

	def verify_query(self, query_string):

		kv_dict = {}
		kv_list = query_string[5:].split('&')
		for kv in kv_list:
			key, value = kv.split('=')
			kv_dict[key] = value

		filename = kv_dict['file']
		hmac0 = cryptopals.to_hex(cryptopals.hmac.hmac_sha1(self.key, filename))
		hmac1 = kv_dict['signature']

		if _insecure_compare(hmac0, hmac1):
			return 200
		else:
			return 500

# ------------------------------------------------------------------------------

#
#	NB: I do all the comparisons on hex-characters instead of byte-by-byte
#	to bring down the running time (20*256^2 -> 40*16^2) by a factor or 128
#

SIGNATURE_SIZE = 40


def get_hex_char(n):
	return "0123456789abcdef"[n]


def generate_query(filename, hmac):
	query = "test?file=%s&signature=%s" % (filename, ''.join(hmac))
	return query


api = Api()

filename = "filename"


#
#  for comparison, print the HMAC of filename
#
''
hmac0 = cryptopals.hmac.hmac_sha1(api.key, filename)
print cryptopals.to_hex(hmac0)

hmac = ['.'] * SIGNATURE_SIZE
for i in xrange(SIGNATURE_SIZE):

	max_t = 0
	max_n = 0

	for n in xrange(16):
		hmac[i] = get_hex_char(n)
		query = generate_query(filename, hmac)
#		query = "test?file=%s&signature=%s" % (filename, ''.join(hmac))

		t0 = time.time()
		res = api.verify_query(query)
		t1 = time.time()

		t = t1 - t0
		if t > max_t:
			max_t = t
			max_n = n

	hmac[i] = get_hex_char(max_n)
	print '\r' + ''.join(hmac),


import cryptopals
import cryptopals.hmac
import time


# ------------------------------------------------------------------------------

def _insecure_compare(s1, s2):

	for n in xrange(len(s1)):
		if s1[n] != s2[n]:
			return False
		time.sleep(0.005)

	return True


class Api(object):

	def __init__(self):
		self.key = cryptopals.get_random_key(16)

	def verify_query(self, query_string):

		kv_dict = {}
		kv_list = query_string[5:].split('&')
		for kv in kv_list:
			k, v = kv.split('=')
			kv_dict[k] = v
	
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


def regression(stat):

	sum_xx = 0
	sum_xy = 0
	sum_x  = 0
	sum_y  = 0

	n = 0
	for x, list_y in enumerate(stat):
		for y in list_y:
			sum_xx += x*x
			sum_xy += x*y
			sum_x  += x
			sum_y  += y
			n += 1

	ss_xy = n * sum_xy - (sum_x * sum_y)
	ss_xx = n * sum_xx - (sum_x * sum_x)

	b1 = float(ss_xy) / ss_xx
	b0 = (sum_y - b1 * sum_x) / n
	return b0, b1


def generate_query(filename, hmac):
	query = "test?file=%s&signature=%s" % (filename, ''.join(hmac))
	return query


def signature_attack():

	api = Api()

	filename = "filename"
	hmac0 = cryptopals.hmac.hmac_sha1(api.key, filename)
	print cryptopals.to_hex(hmac0)

	stat = [[] for n in xrange(SIGNATURE_SIZE + 1)]
	b0 = 0	# 0.003190497815748307
	b1 = 1	# 0.017901323009812484

	hmac = ['.'] * SIGNATURE_SIZE
	for i in xrange(SIGNATURE_SIZE):

		max_t = 0
		max_n = 0

		times = []

		for n in xrange(16):
			hmac[i] = get_hex_char(n)
			query = generate_query(filename, hmac)

			def time_it(q):
				t0 = time.time()
				res = api.verify_query(q)
				res = api.verify_query(q)
				t1 = time.time()
				return t1 - t0

			t = [time_it(query) for tt in xrange(5)]
			times.append(t)
			median_t = sorted(t)[3]

			if i != 0:
				if int(0.5 + (median_t - b0) / b1) == (i + 1):
					max_n = n
					break
			else:
				if median_t > max_t:
					max_t = median_t
					max_n = n

		stat[i+1].extend(times[max_n])
		times[max_n] = []
		for t in times:
			stat[i].extend(t)

		# run linear regression again
		b0, b1 = regression(stat)

		hmac[i] = get_hex_char(max_n)
		print '\r' + ''.join(hmac),

	query = generate_query(filename, hmac)
	if api.verify_query(query) == 200:
		print "Yay!"
	else:
		print "Nay!"

for x in xrange(10):
	signature_attack()

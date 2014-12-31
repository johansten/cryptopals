import cryptopals

mt    = cryptopals.MersenneTwister()
clone = cryptopals.MersenneTwister()

mt.seed(4711)

# get output from "mt" and untemper

for n in xrange(mt.n):
	rand = mt.rand_int32()
	clone.mt[n] = cryptopals.mt_untemper(rand)

clone.i = mt.n

# run the two random number generators side by side

for n in xrange(10):
	print mt.rand_int32(), clone.rand_int32()

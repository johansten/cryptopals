import cryptopals

mt = cryptopals.MersenneTwister()
mt.seed(4711)
print mt.rand_int32()

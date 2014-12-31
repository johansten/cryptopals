
import cryptopals
import time
import random


print "Waiting"
time.sleep(random.randint(4, 10))
timestamp0 = int(time.time())


mt = cryptopals.MersenneTwister()
mt.seed(timestamp0)
random_output = mt.rand_int32()
print "RNG output:", random_output

time.sleep(random.randint(10, 20))
timestamp = int(time.time())

while True:
	mt.seed(timestamp)
	if random_output == mt.rand_int32():
		break
	timestamp -= 1

print "Seed value:", timestamp





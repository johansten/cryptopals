
import cryptopals


f = open("4.txt", "r")
lines = f.readlines()
f.close()

min_sum = 480
min_xor = -1
min_raw = None
for line in lines:
	raw = line.strip().decode('hex')
	sum, xor = cryptopals.find_single_byte_xor(raw)

	if sum < min_sum:
		min_sum = sum
		min_xor = xor
		min_raw = raw

print cryptopals.xor_with_single_byte(min_raw, min_xor)

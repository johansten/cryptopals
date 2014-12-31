import cryptopals

f = open("8.txt", "rb")
lines = f.readlines()
f.close()

for index, line in enumerate(lines):
	raw = line.strip().decode('hex')
	if cryptopals.is_ecb(raw):
		print 'line #%d is ECB' % index

import cryptopals
import cryptopals.sha1

key = cryptopals.get_random_key(32)

data = "Ice Ice Baby"

s1 = cryptopals.sha1.SHA1()
s1.update(key + data)
print cryptopals.to_hex(s1.finish())

s1 = cryptopals.sha1.SHA1()
s1.update(key + data + ".")
print cryptopals.to_hex(s1.finish())

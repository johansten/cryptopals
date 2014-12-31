
import cryptopals

s1 = "ICE ICE BABY\x05\x05\x05\x05"
s2 = "ICE ICE BABY\x04\x04\x04\x04"
s3 = "ICE ICE BABY\x01\x02\x03\x04"

print cryptopals.is_valid_pkcs7(s1)
print cryptopals.is_valid_pkcs7(s2)
print cryptopals.is_valid_pkcs7(s3)

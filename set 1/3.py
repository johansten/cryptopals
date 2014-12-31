
import cryptopals

raw = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
raw = raw.decode('hex')

min_sum, min_xor = cryptopals.find_single_byte_xor(raw)
print min_sum, cryptopals.xor_with_single_byte(raw, min_xor)

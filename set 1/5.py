import cryptopals

plain_text = (
	"Burning 'em, if you ain't quick and nimble\n"
	"I go crazy when I hear a cymbal"
)
key = "ICE"

print cryptopals.to_hex(cryptopals.xor_repeating_key(plain_text, key))

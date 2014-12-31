import cryptopals
import base64


base64_text = (
	"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"
	"2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
)

cipher_text = base64.standard_b64decode(base64_text)

key = "YELLOW SUBMARINE"
nonce = 0

print cryptopals.encrypt_ctr(cipher_text, key, nonce)

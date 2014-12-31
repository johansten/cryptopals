
import cryptopals
import base64

# ------------------------------------------------------------------------------

f = open("7.txt", "rb")
base64_text = f.read()
f.close()

key = "YELLOW SUBMARINE"

cipher_text	= base64.standard_b64decode(base64_text)
plain_text  = cryptopals.decrypt_ebc(cipher_text, key)
print plain_text

# ------------------------------------------------------------------------------


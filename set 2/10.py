
import cryptopals
import base64


# ------------------------------------------------------------------------------

f = open("10.txt", "rb")
base64_text = f.read()
f.close()
raw = base64.standard_b64decode(base64_text)

key = "YELLOW SUBMARINE"
iv = '\0' * 16

plain  = cryptopals.decrypt_cbc(raw, key, iv)
cipher = cryptopals.encrypt_cbc(plain, key, iv)
print cryptopals.decrypt_cbc(cipher, key, iv)

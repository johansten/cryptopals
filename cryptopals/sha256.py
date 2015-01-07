
import hashlib


class SHA256():

	def __init__(self):
		self.m = hashlib.sha256()

	def update(self, data):
		self.m.update(data)

	def finish(self):
		return self.m.digest()

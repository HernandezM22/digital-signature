from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

message = 'To be signed'
a = message.encode("utf-8")
key = RSA.import_key(open('private.pem').read())
h = SHA256.new(a)
signature = pss.new(key).sign(h)


key = RSA.import_key(open('public.pem').read())
h = SHA256.new(a)
verifier = pss.new(key)
try:
    verifier.verify(h, signature)
    print ("The signature is authentic.")
except (ValueError, TypeError):
    print ("The signature is not authentic.")
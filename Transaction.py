#
#

from collections import OrderedDict
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Transaction(object):
    
    def __init__(self, sender, sender_key, recipient, amount):
        self.sender = sender
        self.sender_key = sender_key
        self.recipient = recipient
        self.amount = amount
        return

    def __getattr__(self, attr):
        return self.data[attr]

    def makeDict(self):
        return OrderedDict({
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount
        })

    def signTransaction(self):
        privaye_key = RSA.importKey(binascii.unhexlify(self.sender_key))
        signer = PKCS1_v1_5.new(privaye_key)
        h = SHA.new(str(self.makeDict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

# EOF
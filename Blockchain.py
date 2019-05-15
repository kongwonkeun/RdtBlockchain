#
#

from collections import OrderedDict
import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests


MINING_SENDER = 'BLOCKCHAIN'
MINING_REWARD = 1
MINING_DIFFICULTY = 2

class Blockchain(object):
    
    def __init__(self):
        self.transactions = []
        self.chains = []
        self.nodes = set()
        self.createNewBlock(0, '00') #---- create the genesis block
        return

    def registerNode(self, address): #---- address eg. 'http://192.168.0.5:5000'
        url = urlparse(address)
        if url.netloc:
            self.nodes.add(url.netloc)
        elif url.path:
            self.nodes.add(url.path)
        else:
            raise ValueError('invalid url')
        return

    def validateBlockchain(self, chains):
        last_block = chains[0]
        index = 1
        while index < len(chains):
            block = chains[index]
            #print(f'{block}')
            if block['previous_hash'] != self.generateHash(last_block):
                return False
            transactions = block['transactions'][:-1]
            transaction_elements = ['sender', 'recipient', 'amount']
            transactions = [OrderDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]
            if not self.validateProof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False
            last_block = block
            index += 1
        return True

    def resolveConflicts(self):
        nodes = self.nodes
        chains = None
        length = len(self.chains)
        for node in nodes:
            response = requests.get(f'http://{node}/blockchain/chains')
            if response.status_code == 200:
                l = response.json()['length']
                c = response.json()['chains']
                if l > length and self.validateBlockchain(c):
                    length = l
                    chains = c
        if chains:
            self.chains = chains
            return True
        return False

    def createNewBlock(self, nonce, previous_hash):
        block = {
            'index': len(self.chains) + 1,
            'timestamp': time(),
            'transactions': self.transactions,
            'nonce': nonce,
            'previous_hash': previous_hash,
        }
        self.transactions = []
        self.chains.append(block)
        return block

    def verifyTransactionSignature(self, sender, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))

    def createNewTransaction(self, sender, recipient, amount, signature):
        transaction = OrderedDict({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        if sender == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chains) + 1
        else:
            transaction_verification = self.verifyTransactionSignature(sender, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chains) + 1
        return False

    def solveProofOfWork(self):
        last_block = self.chains[-1]
        last_hash = self.generateHash(last_block)
        nonce = 0
        while self.validateProof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce

    def generateHash(self, block):
        block_string = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def validateProof(self, transactions, last_hash, nonce, difficulty = MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0'*difficulty

# EOF
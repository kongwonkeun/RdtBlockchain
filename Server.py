#
#

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
from flask import Flask, url_for, jsonify, request, render_template, make_response, redirect, session
from flask_sqlalchemy import SQLAlchemy

from Blockchain import Blockchain, MINING_SENDER, MINING_REWARD
from Transaction import Transaction

m_app = Flask(__name__) #---- instantiate node
m_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rdtone.db'
m_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
m_db = SQLAlchemy(m_app)

m_private_key = RSA.generate(1024, Crypto.Random.new().read)
m_public_key = m_private_key.publickey()
m_key = binascii.hexlify(m_private_key.exportKey(format = 'DER')).decode('ascii')
m_id = binascii.hexlify(m_public_key.exportKey(format = 'DER')).decode('ascii')

m_blockchain = Blockchain()


#
#   /
#
@m_app.route('/')
def home():
    user_name = request.cookies.get('MY_USER')
    if not session.get('logged_in'):
        return render_template('./index.html')
    return render_template('./index.html', user = user_name)

#
#   /login
#
@m_app.route('/login', methods = ['GET', 'POST'])
def login():
    user_name = request.cookies.get('MY_USER')
    if request.method == 'GET':
        return render_template('./login.html', user = user_name)
    else: # 'POST'
        name = request.form['username']
        password = request.form['password']
        if User.isValidUser(name, password) == True:
            session['logged_in'] = True
            response = make_response(render_template('./index.html', user = name))
            response.set_cookie('MY_USER', name)
            return response
    return render_template('./login.html', data = 'you are not allowed to login')

#
#   /logout
#
@m_app.route('/logout')
def logout():
    session['logged_in'] = False
    response = make_response(render_template('./index.html'))
    response.delete_cookie('MY_USER')
    return response

#
#   /reg
#
@m_app.route('/reg', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['username']
        password = request.form['password']
        if User.registerUser(name, password) == True:
            return render_template('./login.html', data = 'you are registered')
        else:
            return render_template('./login.html', data = 'you are already restered')
    return render_template('./register.html')

#
#   /mining
#
@m_app.route('/mining')
def mining():
    user_name = request.cookies.get('MY_USER')
    return render_template('./mining.html', user = user_name)

#
#   /transaction
#
@m_app.route('/transaction')
def transaction():
    user_name = request.cookies.get('MY_USER')
    return render_template('./transaction.html', user = user_name)

#
#   /user/users
#
@m_app.route('/user/users')
def users():
    user_all = User.getUsers()
    users = []
    for x in user_all:
        user = {
            'id': x.u_id,
            'name': x.u_name,
            'password': x.u_password,
            'private_key': x.u_private_key,
            'public_key': x.u_public_key,
            'coin': x.u_coin,
        }
        users.append(user)
    size = len(users)
    data = json.loads(json.dumps(users))
    return render_template('./users.html', data = data, size = size)

#
#   /user/generate_wallet
#
@m_app.route('/user/generate_wallet')
def genUserWallet():
    user_name = request.cookies.get('MY_USER')
    return render_template('./wallet_generate.html', user = user_name)

#
#   /transaction/generate
#
@m_app.route('/transaction/generate', methods = ['POST'])
def generateTransaction():
    sender = request.form['sender']
    sender_key = request.form['sender_key']
    recipient = request.form['recipient']
    amount = request.form['amount']
    transaction = Transaction(sender, sender_key, recipient, amount)
    response = {
        'transaction': transaction.makeDict(),
        'signature': transaction.signTransaction(),
    }
    return jsonify(response), 200

#
#   /transaction/make
#
@m_app.route('/transaction/make', methods = ['POST'])
def makeTransaction():
    sender = User.getPublicKey(request.form['sender'])
    sender_key = User.getPrivateKey(request.form['sender'])
    recipient = User.getPublicKey(request.form['recipient'])
    amount = request.form['amount']
    return render_template('./transaction_make.html', sender = sender, sender_key = sender_key, recipient = recipient, amount = amount)

#
#   /transaction/view
#
@m_app.route('/transaction/view')
def viewTransaction():
    return render_template('./transaction_view.html')

#
#   /transaction/transactions
#
@m_app.route('/transaction/transactions')
def getTransaction():
    transactions = m_blockchain.transactions
    response = {
        'transactions': transactions,
    }
    return jsonify(response), 200

#
#   /wallet/generate
#
@m_app.route('/wallet/generate')
def generateWallet():
    random_num = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_num)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format = 'DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format = 'DER')).decode('ascii'),
    }
    return jsonify(response), 200

#
#   /wallet/save
#
@m_app.route('/wallet/save', methods = ['POST'])
def saveWallet():
    values = request.form
    User.registerWallet(values['user_name'], values['pri_key'], values['pub_key'])
    response = {
        'return': True
    }
    return jsonify(response), 200

#
#   /wallet/show/<user_name>
#
@m_app.route('/wallet/show/<user_name>')
def showWallet(user_name):
    private_key = User.getPrivateKey(user_name)
    public_key = User.getPublicKey(user_name)
    return render_template('./wallet_show.html', user = user_name, pri_key = private_key, pub_key = public_key)

#
#   /wallet/show
#
@m_app.route('/wallet/show')
def showWallet_():
    user_name = request.cookies.get('MY_USER')
    private_key = User.getPrivateKey(user_name)
    public_key = User.getPublicKey(user_name)
    return render_template('./wallet_show.html', user = user_name, pri_key = private_key, pub_key = public_key)

#
#   /blockchain/mine
#
@m_app.route('/blockchain/mine', methods = ['GET', 'POST'])
def mine():
    if request.method == 'GET':
        miner = m_id
    else:
        miner = User.getPublicKey(request.form['user_name'])
    last_block = m_blockchain.chains[-1]
    nonce = m_blockchain.solveProofOfWork()
    m_blockchain.createNewTransaction(
        sender = MINING_SENDER,
        recipient = miner,
        amount = MINING_REWARD,
        signature = "",
    )
    previous_hash = m_blockchain.generateHash(last_block)
    block = m_blockchain.createNewBlock(nonce, previous_hash)
    response = {
        'message': 'new block forged',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

#
#   /blockchain/transact
#
@m_app.route('/blockchain/transact', methods = ['POST'])
def createNewTransaction():
    values = request.form
    required = [
        'sender', 
        'recipient', 
        'amount',
        'signature',
    ]
    if not all(k in values for k in required):
        return 'missing values', 400
    index = m_blockchain.createNewTransaction(values['sender'], values['recipient'], values['amount'], values['signature']) #---- create now transaction
    response = {
        'message': f'transaction will be added to block {index}',
    }
    return jsonify(response), 201

#
#   /blockchain/chains
#
@m_app.route('/blockchain/chains')
def getFullChain():
    response = {
        'chains': m_blockchain.chains,
        'length': len(m_blockchain.chains),
    }
    return jsonify(response), 200

#
#   /blockchain/resolve
#
@m_app.route('/blockchain/resolve')
def resolve():
    replaced = m_blockchain.resolveConflicts()
    if replaced:
        response = {
            'message': 'our chain was replaced',
            'new_chains': m_blockchain.chains,
        }
    else:
        response = {
            'message': 'our chain is authoritative',
            'chains': m_blockchain.chains,
        }
    return jsonify(response), 200

#
#   /node/register
#
@m_app.route('/node/register', methods = ['POST'])
def registerNodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return 'error: please supply a valid list of nodes', 400
    for node in nodes:
        m_blockchain.registerNode(node)
    response = {
        'message': 'new nodes have been added',
        'nodes': list(m_blockchain.nodes),
    }
    return jsonify(response), 201

#
#   /node/nodes
#
@m_app.route('/node/nodes')
def getFullNode():
    nodes = list(m_blockchain.nodes)
    response = {
        'nodes': nodes,
    }
    return jsonify(response), 200

#
#   DATABASE TABLE
#
class User(m_db.Model):

    u_id = m_db.Column(m_db.Integer, primary_key = True)
    u_name = m_db.Column(m_db.String, unique = True)
    u_password = m_db.Column(m_db.String)
    u_private_key = m_db.Column(m_db.String)
    u_public_key = m_db.Column(m_db.String)
    u_coin = m_db.Column(m_db.Integer)

    def __init__(self, name, password):
        self.u_name = name
        self.u_password = password
        self.u_coin = 0
        return
    
    @classmethod
    def isValidUser(cls, name, password):
        data = User.query.filter_by(u_name = name, u_password = password).first()
        if data is not None:
            return True
        return False

    @classmethod
    def registerUser(cls, name, password):
        data = User.query.filter_by(u_name = name).first()
        if data is None:
            user = User(name, password)
            m_db.session.add(user)
            m_db.session.commit()
            return True
        return False

    @classmethod
    def registerWallet(cls, name, private_key, public_key):
        data = User.query.filter_by(u_name = name).first()
        data.u_private_key = private_key
        data.u_public_key = public_key
        m_db.session.commit()
        return True
    
    @classmethod
    def registerNode(cls):
        data = User.query.filter_by(u_name = 'BLOCKCHAIN').first()
        if data is None:
            user = User('BLOCKCHAIN', 'blockchain_admin')
            user.u_private_key = m_key
            user.u_public_key = m_id
            m_db.session.add(user)
            m_db.session.commit()
            return True
        return False

    @classmethod
    def getPrivateKey(cls, name):
        data = User.query.filter_by(u_name = name).first()
        return data.u_private_key

    @classmethod
    def getPublicKey(cls, name):
        data = User.query.filter_by(u_name = name).first()
        return data.u_public_key

    @classmethod
    def getUsers(cls):
        return User.query.all()

    @classmethod
    def test(cls):
        for user in User.query.all():
            print('%s, %s, %s, %s, %s, %s' % (
                user.u_id, 
                user.u_name, 
                user.u_password, 
                user.u_private_key, 
                user.u_public_key,
                user.u_coin,
            ))
        return

#
#   MAIN
#
if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default = 5000, type = int, help = 'port to listen on')
    args = parser.parse_args()
    p = args.port
    m_db.create_all()
    m_app.secret_key = 'root'
    User.registerNode()
    #User.test()
    m_app.run(host = '0.0.0.0', port = p)

# EOF

import hashlib as hasher
import datetime as date
import os

from flask import Flask,request,redirect,url_for,render_template,session,abort
node = Flask(__name__)

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        sha = hasher.sha256()
        sha.update(str(self.index).encode('utf-8') + 
                    str(self.timestamp).encode('utf-8') + 
                    str(self.data).encode('utf-8') + 
                    str(self.previous_hash).encode('utf-8'))
        return sha.hexdigest()

##################################################

# Generate genesis block
def create_genesis_block():
    # Manually construct a block with index zero and arbitrary previous hash
    return Block(0, 
                date.datetime.now(), 
                {
                    "proof-of-work": 9,
                    "transactions": None
                }, 
                "0")

                
# A completely random address of the owner of this node
miner_address = "q3nf394hjg-random-miner-address-34nf3i4nflkn3oi"

# This node's blockchain copy
blockchain = []
blockchain.append(create_genesis_block())

# Store the transactions that this node has in a list
this_nodes_transactions = []

# Store the url data of every other node in the network so that we can communicate with them
peer_nodes = []

# A variable to deciding if we're mining or not
mining = True                


##################################################

def proof_of_work(last_proof):
    # Create a variable that we will use to find our next proof of work
    incrementor = last_proof + 1
    # Algo : Keep incrementing incrementor until it's equal to number divisible by 9 & the proof of work of previous block in the chain
    while not (incrementor % 9 == 0 and incrementor % last_proof == 0):
        incrementor += 1
    # Once that number is found, we can return it as a proof of our work
    return incrementor


@node.route('/txion', methods=['POST'])
def transaction():
    if request.method == 'POST':
        # On each new POST request, extract the transaction data & Add the transaction to our list
        new_txion = request.get_json()
        this_nodes_transactions.append(new_txion)

        print("New transaction")
        print("FROM: {}".format(new_txion['from']))
        print("TO: {}".format(new_txion['to']))
        print("AMOUNT: {}\n".format(new_txion['amount']))
        # Let the client know it worked out
        return "Transaction submission successful\n"


@node.route('/mine', methods = ['GET'])
def mine():
    # Get the last proof of work
    last_block = blockchain[len(blockchain) - 1]
    last_proof = last_block.data['proof-of-work']
    # Find the proof of work for current block being mined
    # The program will hang here until a new proof of work is found
    proof = proof_of_work(last_proof)
    # Once we find a valid proof of work, we know we can mine a block so we reward the miner by adding a transaction
    this_nodes_transactions.append({ "from": "network", "to": miner_address, "amount": 1 })
    
    # Now we can gather the data needed to create the new block
    new_block_data = {
    "proof-of-work": proof,
    "transactions": list(this_nodes_transactions)
    }
    new_block_index = last_block.index + 1
    new_block_timestamp = this_timestamp = date.datetime.now()
    last_block_hash = last_block.hash
    
    # Empty transaction list
    this_nodes_transactions[:] = []
    
    # Now create the new block
    mined_block = Block(
    new_block_index,
    new_block_timestamp,
    new_block_data,
    last_block_hash
    )
    blockchain.append(mined_block)
    
    # Let the client know we mined a block
    return json.dumps({
        "index": new_block_index,
        "timestamp": str(new_block_timestamp),
        "data": new_block_data,
        "hash": last_block_hash
    }) + "\n"


@node.route('/blocks', methods=['GET'])
def get_blocks():
    chain_to_send = blockchain

    # Convert our blocks into dictionaries so we can send them as json objects later
    for i in range(len(chain_to_send)):
        block = chain_to_send[i]
        block_index = str(block.index)
        block_timestamp = str(block.timestamp)
        block_data = str(block.data)
        block_hash = block.hash
        chain_to_send[i] = {
            "index": block_index,
            "timestamp": block_timestamp,
            "data": block_data,
            "hash": block_hash
        }
    chain_to_send = json.dumps(chain_to_send)

    return chain_to_send


def find_new_chains():
    # Get the blockchains of every other node
    other_chains = []

    for node_url in peer_nodes:
        # Get their chains using a GET request
        block = requests.get(node_url + "/blocks").content
        # Convert the JSON object to a Python dictionary
        block = json.loads(block)
        # Add it to our list
        other_chains.append(block)

    return other_chains


def consensus():
    # Get the blocks from other nodes
    other_chains = find_new_chains()

    # If our chain isn't longest, then we store the longest chain
    longest_chain = blockchain
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
        # If the longest chain isn't ours, then we stop mining and set our chain to the longest one
    blockchain = longest_chain

##################################################

creds = {'admin':'1234'}
cur_user = ""

@node.route('/profile/<name>')
def profile(name):
    return 'Welcome %s' % name


@node.route('/login')
def login():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return '%s already logged in! <a href="/logout">Logout</a>' % cur_user


@node.route("/logout")
def logout():
    session['logged_in'] = False
    return render_template('login.html')


@node.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if username in creds and creds[username] == password:
        session['logged_in'] = True
        cur_user = username
        return redirect(url_for('profile', name = username))
    else:
        return 'Login error. Incorrect username/password'


node.secret_key = os.urandom(12)
node.run(host='192.168.1.130', port='5050', debug = True)
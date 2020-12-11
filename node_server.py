from hashlib import sha256
import jsonpickle
import json
import string
import threading
import time
import numpy
import random
import base64
import sys
from math import log
from flask import Flask, request
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# TODO flag for miner and validator
global tx_string
tx_string = str(random.choices(string.ascii_uppercase + string.digits, k=10000))


f = 1


def key_gen():
    private_key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    return private_key


class Block:
    def __init__(self, height, transactions, timestamp, previous_hash, previous_qc, nonce=0):
        self.height = height
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.previous_qc = previous_qc
        self.nonce = nonce

    def to_json(self):
        return jsonpickle.encode(self)


class BlockProps:
    def __init__(self, block, parent_idx):
        self.block = block
        self.parent_idx = parent_idx
        self.votes = []
        self.certified = False
        self.committed = False
        self.cert_count = 0
        self.comm_count = 0

    def commit(self):
        self.committed = True

    def certify(self):
        self.certified = True

    def add_vote(self, pure_vote, pub_key, coded_vote, signature):
        """
        This function adds the vote to the block props of a block
        :param pure_vote: the vote itself
        :param pub_key: public key of the voter of the vote
        :param coded_vote: a string consisting of: height of the block + pure vote + hash of the block
        :param signature: signature of the coded vote by the voter
        :return: True if vote is successfully added and False if vote is discarded
        """
        for prev_coded_vote, prev_signature in self.votes:
            if prev_signature == signature:
                return False
        if pure_vote == "cert":
            self.cert_count = self.cert_count + 1
        elif pure_vote == "comm":
            self.comm_count = self.comm_count + 1
            self.cert_count = self.cert_count + 1
        elif pure_vote != "cert" and pure_vote != "comm":
            return False

        self.votes.append([coded_vote, signature])

        thread("propagate_vote", {"coded_vote": coded_vote, "signature": signature})

        return True

    def to_json(self):
        return jsonpickle.encode(self)


class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 0

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = {}
        self.is_mining = False
        self.newly_received_block = False

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0, [], 0, 0, [], "0")
        # self.chain.append(genesis_block)
        self.chain[0] = []
        genesis_block_props = BlockProps(genesis_block, None)
        genesis_block_props.certify()
        genesis_block_props.commit()
        genesis_block_props.votes = []
        self.chain[0].append(genesis_block_props)

    def search_hash(self, height, prev_hash, node_address):
        # TODO: delete node_address from interface (here and verify_and_add_block_method)
        """
        A function that searches for "prev_hash" block hash in the blocks of height "height"
        :return: index of the block with hash "prev_hash" in height "height"
        """
        parent_idx = None
        if len(self.chain) >= height:
            for i in range(0, len(self.chain[height - 1])):
                if prev_hash == compute_hash(self.chain[height - 1][i].block):
                    parent_idx = i
                    return parent_idx
        return parent_idx

    def add_block(self, block_props, parent_idx):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * The block is not a duplicate.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        * Checking if the proof is valid.
        * Checking if previous QC is valid.
        Then, the function decides for the vote and adds it to the self blockchain.
        Finally, it propagates the vote.
        """

        block_props.parent_idx = parent_idx

        block_height = block_props.block.height

        # check if the block is duplicated => discard it TODO do it below when appending -> with hash
        if len(blockchain.chain) > block_height:
            for existing_block_props in blockchain.chain[block_height]:
                if compute_hash(block_props.block) == compute_hash(existing_block_props.block):
                    return True

        # check the previous hash
        previous_hash = compute_hash(self.chain[block_height - 1][parent_idx].block)
        if previous_hash != block_props.block.previous_hash:
            print("prev hash error")
            return False

        # check if the proof is valid
        if not Blockchain.is_valid_proof(block_props.block):
            print("proof error")
            return False

        # check if QC is valid TODO make it a function
        if block_props.block.height != 1:

            if len(block_props.block.previous_qc) < (2 * f + 1):
                print("qc error 1")
                return False

            pub_key_set = []
            correct_votes_number = 0

            for vote in block_props.block.previous_qc:
                coded_vote, signature = vote

                decoded_pure_vote, decoded_block, decoded_block_height, decoded_pub_key, decoded_block_hash = decode(
                    coded_vote, signature)
                if decoded_pub_key in pub_key_set or decoded_pure_vote is None:
                    continue
                else:
                    pub_key_set.append(decoded_pub_key)
                    self.chain[decoded_block_height][block_props.parent_idx].add_vote(decoded_pure_vote,
                                                                                      decoded_pub_key, coded_vote,
                                                                                      signature)
                    correct_votes_number = correct_votes_number + 1

                if compute_hash(self.chain[decoded_block_height][block_props.parent_idx].block) \
                        != decoded_block_hash:
                    print("qc error 2")
                    return False
            if correct_votes_number < (2 * f + 1):
                print("qc error 3")
                return False

        # add the block to the chain
        if len(self.chain) < (block_height + 1):
            self.chain[block_height] = []
            self.newly_received_block = True
        else:
            for i in range(0, len(self.chain[block_height])):
                if self.chain[block_height][i].block == block_props.block:
                    print("block already existed!!!")
                    return True
        self.chain[block_height].append(block_props)

        # find the index of the added block
        block_idx = 0
        for block_props_ in self.chain[block_height]:
            if block_props_ == block_props:
                break
            block_idx += 1

        # print the blockchain
        print("block " + str(block_height) + " was appended successfully")
        for i in range(0, len(blockchain.chain)):
            print("Height " + str(i) + " has " + str(len(blockchain.chain[i])) + " blocks")

        # Send the block props of the added block to others
        thread("propagate_block_props", {"block_props": block_props})

        # Voting TODO make it a function
        if block_props.certified is False:
            # decide the vote for the added block
            if block_height > 1:
                conflict_num_grand_parent = 0
                conflict_num_parent = 0
                for block_prop in self.chain[block_height - 2]:
                    if block_prop.certified:
                        conflict_num_grand_parent = conflict_num_grand_parent + 1
                for block_prop in self.chain[block_height - 1]:
                    if block_prop.certified:
                        conflict_num_parent = conflict_num_parent + 1
                if conflict_num_grand_parent > 1 or conflict_num_parent > 1:
                    pure_vote = "cert"
                else:
                    pure_vote = "comm"
            else:
                pure_vote = "comm"

            # add the vote to the node's own blockchain
            coded_vote, signature = code(pure_vote, block_props.block)
            self.chain[block_height][block_idx].add_vote(pure_vote, self_public_key, coded_vote, signature)
            if not self.chain[block_height][block_idx].certified:
                if blockchain.chain[block_height][block_idx].cert_count > (2 * f):
                    certify_block(blockchain.chain[block_height][block_idx], block_idx)
            if block_height > 2:
                parent_idx = blockchain.chain[block_height][block_idx].parent_idx
                grandparent_idx = blockchain.chain[block_height - 1][parent_idx].parent_idx
                if not blockchain.chain[block_height - 2][grandparent_idx].committed:
                    if blockchain.chain[block_height][block_idx].comm_count > (2 * f):
                        commit_block(blockchain.chain[block_height - 2][grandparent_idx], True)
        return True

    @staticmethod
    def proof_of_work(block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        # A random delay instead of high difficulty
        random_delay(sec)

        block.nonce = 0

        computed_hash = compute_hash(block)
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = compute_hash(block)

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        return compute_hash(block).startswith('0' * Blockchain.difficulty)

    def search_for_certified(self, height):
        """
        Finds the last certified block in the blockchain
        """
        last_block = None
        last_block_height = height
        number_of_blocks = len(self.chain[height])
        for i in range(0, number_of_blocks):
            if self.chain[height][i].certified:
                last_block_props = self.chain[height][i]
                last_block_idx = i
                last_block = last_block_props.block
                break
        if last_block is None:
            last_block_props, last_block_idx, last_block_height = self.search_for_certified(height - 1)
        return last_block_props, last_block_idx, last_block_height

    def mine(self):
        """
        Puts all unconfirmed transactions in a block, finds the last certified block,
        and builds the block on top of it.
        Then, adds the block to its own blockchain.
        :return:  the new proposed block and its index
        """
        if not self.unconfirmed_transactions:
            return False, None, None

        height = len(self.chain) - 1
        last_block_props, last_block_idx, blockchain_length = self.search_for_certified(height)

        new_block = Block(height=blockchain_length + 1,
                          transactions=self.unconfirmed_transactions[0:number_of_block_transactions],
                          timestamp=time.time(),
                          previous_hash=compute_hash(last_block_props.block),
                          previous_qc=last_block_props.votes)

        block_props = BlockProps(new_block, last_block_idx)

        self.proof_of_work(new_block)
        if self.newly_received_block is True:
            self.newly_received_block = False
            return False, False, None

        self.add_block(block_props, last_block_idx)

        self.unconfirmed_transactions = self.unconfirmed_transactions[number_of_block_transactions:]
        print("new len of unconfirmed_transactions: ", len(self.unconfirmed_transactions))

        self.is_mining = False

        return True, new_block, last_block_idx


app = Flask(__name__)


def new_transaction():
    """
    Makes a new transaction and propagates it
    """
    # tx_data = {"data": "Bingo!"}
    tx_data = {"data": tx_string}
    tx_data["timestamp"] = time.time()
    thread("propagate_tx", {"tx_data": tx_data})


##################################### write comments from here #####################################


@app.route('/get_transaction', methods=['POST'])
def get_transaction():
    tx_data = request.get_json()['tx_data']
    if time.time() - tx_data['timestamp'] > 10:
        return "Transaction discarded", 400
    if tx_data not in blockchain.unconfirmed_transactions:
        blockchain.add_new_transaction(tx_data)
        thread("propagate_tx", {"tx_data": tx_data})
    # if len(blockchain.unconfirmed_transactions) >= number_of_block_transactions and len(
    #         blockchain.unconfirmed_transactions) % number_of_block_transactions == 0:
    if (blockchain.is_mining is False) and (len(blockchain.unconfirmed_transactions) >= number_of_block_transactions):
        blockchain.is_mining = True
        headers = {'Content-Type': "application/json"}
        response = requests.get("http://127.0.0.1:" + str(port) + "/propose", headers=headers)
        print(response.content)
    return "Successfully received the transaction", 200


@app.route('/get_block', methods=['GET'])
def get_block():
    request_block_data = request.get_json()
    request_height = request_block_data['height']
    print("request came to get a block in height: ", request_height)
    request_hash = request_block_data['hash']
    if len(blockchain.chain) > request_height:
        number_of_blocks = len(blockchain.chain[request_height])
    else:
        return json.dumps({"block_props": "None"})
    requested_block_props = None

    for i in range(0, number_of_blocks):
        if compute_hash(blockchain.chain[request_height][i].block) == request_hash:
            requested_block_props = blockchain.chain[request_height][i]

    if requested_block_props is None:
        return json.dumps({"block_props": "None"})
    else:
        return json.dumps({"block_props": requested_block_props.to_json()})


@app.route('/propose', methods=['GET'])
def propose():
    is_mined, mined_block, last_block_idx = blockchain.mine()
    blockchain.is_mining = False
    if is_mined is False:
        if mined_block is None:
            return "No transactions to mine", 400
        elif mined_block is False:
            return "A new block in a higher height arrived", 400

    if is_mined is False and mined_block is False:
        return "No certified block to mine on it", 400
    else:
        block_props = BlockProps(mined_block, last_block_idx)
        thread("propagate_block_props", {"block_props": block_props})
        for i in range(0, len(blockchain.chain)):
            print("Height " + str(i) + " has " + str(len(blockchain.chain[i])) + " blocks")
        return "Block #{} is proposed.".format(mined_block.height), 200


def extract_signatures():
    sending_signatures = [[[] for i in range(len(blockchain.chain[k]))] for k in range(len(blockchain.chain))]
    for height, _ in enumerate(blockchain.chain):
        for index, _ in enumerate(blockchain.chain[height]):
            for i in range(0, len(blockchain.chain[height][index].block.previous_qc)):
                sending_signatures[height][index].append(
                    base64.b64encode(blockchain.chain[height][index].block.previous_qc[i][1]).decode('ascii'))
    return sending_signatures


def extract_coded_votes():
    sending_coded_votes = [[[] for i in range(len(blockchain.chain[k]))] for k in range(len(blockchain.chain))]
    for height, _ in enumerate(blockchain.chain):
        for index, _ in enumerate(blockchain.chain[height]):
            for i in range(0, len(blockchain.chain[height][index].block.previous_qc)):
                sending_coded_votes[height][index].append(blockchain.chain[height][index].block.previous_qc[i][0])
    return sending_coded_votes


# endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    data = request.get_json()
    node_address = data["node_address"]

    req_chain = data["req_chain"]
    if not node_address:
        return "Invalid data", 400
    if not data["node_key"]:
        return "Invalid key", 400

    # Add the node to the peer list
    sending_peers_list = sending_peers()
    sending_keys = serialize_keys()
    sending_peers_list.add(request.host_url)
    peers.add(node_address)
    add_received_key(data["node_key"])

    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    if req_chain:
        sending_signatures = extract_signatures()
        sending_coded_votes = extract_coded_votes()
        return {"blockchain": jsonpickle.encode(blockchain),
                "signatures": jsonpickle.encode(sending_signatures),
                "coded_votes": jsonpickle.encode(sending_coded_votes),
                "peers": jsonpickle.encode(sending_peers_list),
                "keys": jsonpickle.encode(sending_keys)}, 200
    else:
        return {"peers": jsonpickle.encode(sending_peers_list), "keys": jsonpickle.encode(sending_keys)}, 300


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    register_info = request.get_json()
    node_address = register_info["node_address"]
    req_chain = register_info["req_chain"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url,
            "node_key": base64.b64encode(serialize_pub_key(self_public_key)).decode('ascii'),
            "req_chain": req_chain}
    headers = {'Content-Type': "application/json"}
    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)
    response_data = response.json()

    if response.status_code == 200:
        global blockchain
        global peers
        global keys
        chain_dump = json.loads(response_data['blockchain'])
        received_peers = json.loads(response_data['peers'])
        received_keys = json.loads(response_data['keys'])
        signatures = json.loads(response_data['signatures'])
        coded_votes = json.loads(response_data['coded_votes'])
        deserialize_keys(received_keys)

        create_chain_from_dump(chain_dump['chain'], signatures, coded_votes)


        for i in range(0, len(received_peers["py/set"])):
            peers.add(received_peers["py/set"][i])

        if request.host_url in peers:
            peers.remove(request.host_url)
        print("blockchain: ", len(blockchain.chain))
        print("peers: ", len(peers))
        print("keys:", len(keys))
        return "Registration successful", 200
    elif response.status_code == 300:
        received_peers = json.loads(response_data['peers'])
        received_keys = json.loads(response_data['keys'])
        deserialize_keys(received_keys)
        for i in range(0, len(received_peers["py/set"])):
            peers.add(received_peers["py/set"][i])
        if request.host_url in peers:
            peers.remove(request.host_url)
        print("peers: ", len(peers))
        print("peers: ", peers)
        print("keys:", len(keys))
        return "keys and peers successfully updated", 200
    else:
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code


def create_chain_from_dump(chain_dump, signatures, coded_votes):
    for height in chain_dump.keys():
        print("height = ", str(height) + " has " + str(len(chain_dump[height])) + " block props")
        if int(height) != 0:  # skip genesis block
            for index, block_props in enumerate(chain_dump[height]):
                # make new qc from signatures
                new_previous_qc = []
                for i, _ in enumerate(signatures[int(height)][index]):
                    new_previous_qc.append([coded_votes[int(height)][index][i],
                                            base64.b64decode(signatures[int(height)][index][i])])

                # make a block_props from dump chain
                new_block = Block(block_props['block']['height'], block_props['block']['transactions'],
                                  block_props['block']['timestamp'], block_props['block']['previous_hash'],
                                  new_previous_qc, block_props['block']['nonce'])
                new_block_props = BlockProps(new_block, block_props['parent_idx'])
                new_block_props.votes = block_props['votes']
                new_block_props.certified = block_props['certified']
                new_block_props.committed = block_props['committed']
                new_block_props.cert_count = block_props['cert_count']
                new_block_props.comm_count = block_props['comm_count']
                added = blockchain.add_block(new_block_props,
                                             new_block_props.parent_idx)
            if not added:
                raise Exception("The chain dump is tampered!!")
    return


@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    # get block info
    block_props_json = json.loads(request.get_json())
    block_props = block_props_json_to_class(block_props_json)

    node_address = request.host_url

    if len(blockchain.chain) > block_props.block.height:
        if len(blockchain.chain[block_props.block.height]) == 1:
            if blockchain.chain[block_props.block.height][0].committed:
                return "Block was discarded (already committed)", 400

    # find parent index
    parent_idx = blockchain.search_hash(block_props.block.height, block_props.block.previous_hash, node_address)
    # if parent_idx is not None:
        # print("parent of the received block is found!! --> index: ", parent_idx, "height:", block_props.block.height)

    requested_block_props = None
    msg_code = 201

    if parent_idx is None:
        msg_code = 400
        # print("parent index of the received block was not found :(  We are going to send a request for it... height:",
        #       block_props.block.height)
        # while requested_block_props is None:
        for _ in range(0, retry_request):
            for peer in peers:
                requested_block_props_json = \
                    request_block_props(block_props.block.height - 1, block_props.block.previous_hash,
                                        peer).json()["block_props"]
                requested_block_props = block_props_json_to_class(requested_block_props_json)
                if requested_block_props is not None:
                    # data = {"block": requested_block_props.to_json()}
                    # headers = {'Content-Type': "application/json"}
                    # requests.post(node_address + "/add_block", data=json.dumps(data), headers=headers)
                    msg, msg_code = verify_and_add_block_method(requested_block_props, node_address)
                    break
            if msg_code == 201:
                parent_idx = blockchain.search_hash(block_props.block.height, block_props.block.previous_hash,
                                                    node_address)
                break

    added = False
    if msg_code == 201:
        added = blockchain.add_block(block_props, parent_idx)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


# endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():  # TODO delete?
    return json.dumps(blockchain.unconfirmed_transactions)


# endpoint to receive the votes
@app.route('/receive_vote', methods=['POST'])
def receive_vote():
    coded_vote = request.get_json()["coded_vote"]
    string_signature = request.get_json()["signature"]
    signature = base64.b64decode(string_signature)
    node_address = request.host_url
    requested_block_props = None
    msg_code = 201
    pure_vote, block, block_height, pub_key, block_hash = decode(coded_vote, signature)
    if pub_key is None:
        return "Invalid Public key", 400
    else:
        if block is None:
            msg_code = 400
            # print("The block for the received vote was not found. Let's send a request for it...")
            # while requested_block_props is None:
            for _ in range(0, retry_request):
                for peer in peers:
                    requested_block_props_json_ = request_block_props(block_height, block_hash, peer).json()[
                        "block_props"]
                    if requested_block_props_json_ != "None":
                        requested_block_props_json = json.loads(requested_block_props_json_)
                        requested_block_props = block_props_json_to_class(requested_block_props_json)
                        block = requested_block_props.block

                    if requested_block_props is not None:
                        # print("Got the block for the received vote!")
                        # data = {"block": requested_block_props.to_json()}
                        # headers = {'Content-Type': "application/json"}
                        # requests.post(node_address + "/add_block", data=json.dumps(data), headers=headers)
                        msg, msg_code = verify_and_add_block_method(requested_block_props, node_address)
                        break
                if msg_code == 201:
                    break
    if msg_code == 201:
        idx = get_block_index(block, block.height)
        blockchain.chain[block.height][idx].add_vote(pure_vote, pub_key, coded_vote, signature)
        if not blockchain.chain[block.height][idx].certified:
            if blockchain.chain[block.height][idx].cert_count > (2 * f):
                certify_block(blockchain.chain[block.height][idx], idx)
        if block.height > 2:
            parent_idx = blockchain.chain[block.height][idx].parent_idx
            grandparent_idx = blockchain.chain[block.height - 1][parent_idx].parent_idx
            if not blockchain.chain[block.height - 2][grandparent_idx].committed:
                if blockchain.chain[block.height][idx].comm_count > (2 * f):
                    commit_block(blockchain.chain[block.height - 2][grandparent_idx], True)
        return "Successfully received the vote", 200
    return "The vote was discarded by the node", 400


def verify_and_add_block_method(block_props, node_address):
    if len(blockchain.chain) > block_props.block.height:
        if len(blockchain.chain[block_props.block.height]) == 1:
            if blockchain.chain[block_props.block.height][0].committed:
                return "Block was discarded (already committed)", 400

    # find parent index
    parent_idx = blockchain.search_hash(block_props.block.height, block_props.block.previous_hash, node_address)
    # if parent_idx is not None:
        # print("parent of the received block is found!! --> index: ", parent_idx, " height:", block_props.block.height)

    requested_block_props = None
    msg_code = 201
    if parent_idx is None:
        msg_code = 400
        # print("parent index of the received block was not found :(  We are going to send a request for it... height:",
        #       block_props.block.height)
        # while requested_block_props is None:
        for _ in range(0, retry_request):
            for peer in peers:
                requested_block_props_json = \
                    request_block_props(block_props.block.height - 1, block_props.block.previous_hash,
                                        peer).json()["block_props"]
                requested_block_props = block_props_json_to_class(requested_block_props_json)
                if requested_block_props is not None:
                    # data = {"block": requested_block_props.to_json()}
                    # headers = {'Content-Type': "application/json"}
                    # requests.post(node_address + "/add_block", data=json.dumps(data), headers=headers)
                    msg, msg_code = verify_and_add_block_method(requested_block_props, node_address)
                    break
            if msg_code == 201:
                parent_idx = blockchain.search_hash(block_props.block.height, block_props.block.previous_hash,
                                                    node_address)
                break

    added = False
    if msg_code == 201:
        added = blockchain.add_block(block_props, parent_idx)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


def certify_block(block_props, idx):
    if block_props.certified:
        return
    else:
        blockchain.chain[block_props.block.height][idx].certify()
        certify_block(blockchain.chain[block_props.block.height - 1][block_props.parent_idx], block_props.parent_idx)
    return


def commit_block(block_props, flag):
    # commit the block and prune the blockchain

    # clean the height from other blocks
    height = block_props.block.height
    if flag is False:
        blockchain.chain[height] = [block_props]

    # commit
    blockchain.chain[height][0].certify()
    blockchain.chain[height][0].commit()

    # commit predecessors
    if len(blockchain.chain[height - 1]) > 1 or not blockchain.chain[height - 1][0].committed:
        commit_block(blockchain.chain[height - 1][blockchain.chain[height][0].parent_idx], False)
        blockchain.chain[height][0].parent_idx = 0

    print("**************************************************************************")
    print("**************************************************************************")
    print("Throughput= ", number_of_block_transactions * height / (time.time() - start_time))
    print("**************************************************************************")
    print("**************************************************************************")
    print("Block                             " + str(height) + "                          is committed! ^____________^")

    return


def decode(message, signature):
    is_valid = False
    pure_vote = None
    block = None
    block_height = None
    pub_key = None
    block_hash = None
    for key in keys:
        is_valid = verify_signature(message, signature, key)
        if is_valid is None:
            pub_key = key
            if message.find("cert") > 0:
                start = message.find("cert")
                block_height = int(message[0: start])
                pure_vote = message[start: start + 4]
                block_hash = message[start + 4:]
            if message.find("comm") > 0:
                start = message.find("comm")
                block_height = int(message[0: start])
                pure_vote = message[start: start + 4]
                block_hash = message[start + 4:]
            if message.find("cert") == -1 and message.find("comm") == -1:
                is_valid = False
            break

    if is_valid is False:
        return None, None, None, None, None
    else:
        if len(blockchain.chain) >= block_height:
            for block_props in blockchain.chain[block_height - 1]:
                if compute_hash(block_props.block) == block_hash:
                    block = block_props.block
                    break
        return pure_vote, block, block_height, pub_key, block_hash


def code(pure_vote, block):
    height = str(block.height)
    block_hash = str(compute_hash(block))
    message = height + pure_vote + block_hash
    signature = create_signature(message)
    return message, signature


def create_signature(message):
    signature = self_private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message, signature, public_key):
    is_valid = None
    try:
        is_valid = public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        is_valid = False

    return is_valid


def random_delay(second):
    random_factor = numpy.random.exponential(scale=1, size=None)
    # random_number = randint(0, sec)
    random_number = random_factor * second * (3*f + 1)
    time.sleep(random_number)


def propagate_block_props(block_props):
    peers_list = list(peers)
    for _ in range(0, int(log(len(peers_list) + 1, 2))):
        peer_num = random.randint(0, len(peers_list) - 1)
    # for peer in peers:
        peer = peers_list[peer_num]
        print("peer to send block props with height" + str(block_props.block.height) + " to: " + str(peer))
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block_props.to_json(), sort_keys=True),
                      headers=headers)


def propagate_tx(tx_data):
    peers_list = list(peers)
    for _ in range(0, int(log(len(peers_list) + 1, 2))):
        peer = peers_list[random.randint(0, len(peers_list) - 1)]
        url = "{}get_transaction".format(peer)
        data = {"tx_data": tx_data}
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(data),
                      headers=headers)


def request_block_props(height, block_hash, peer_):
    url = "{}get_block".format(peer_)
    headers = {'Content-Type': "application/json"}
    data = {'height': height, 'hash': block_hash}
    return requests.get(url,
                        data=json.dumps(data),
                        headers=headers)


def propagate_vote(coded_vote, signature):
    peers_list = list(peers)
    for _ in range(0, int(log(len(peers_list) + 1, 2))):
        peer = peers_list[random.randint(0, len(peers_list) - 1)]
    # for peer in peers:
        url = "{}receive_vote".format(peer)
        data = {"coded_vote": coded_vote, "signature": base64.b64encode(signature).decode('ascii')}
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(data),
                      headers=headers)


def get_block_index(block, block_height):
    if len(blockchain.chain) > block_height:
        for i in range(0, len(blockchain.chain[block_height])):
            if compute_hash(block) == compute_hash(blockchain.chain[block_height][i].block):
                return i
    return None


def serialize_pub_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_pub_key(pub_key_serialized):
    return load_pem_public_key(pub_key_serialized)


def serialize_keys():
    serialized_keys_list = []
    for key in keys:
        serialized_keys_list.append(base64.b64encode(serialize_pub_key(key)).decode('ascii'))
    return serialized_keys_list


def deserialize_keys(received_keys):
    for i in range(0, len(received_keys)):
        flag = False
        for key in keys:
            if base64.b64decode(received_keys[i]) == serialize_pub_key(key):
                flag = True
        if flag is False:
            keys.add(deserialize_pub_key(base64.b64decode(received_keys[i])))


def add_received_key(received_key):
    flag = False
    for key in keys:
        if base64.b64decode(received_key) == serialize_pub_key(key):
            flag = True
    if flag is False:
        keys.add(deserialize_pub_key(base64.b64decode(received_key)))


def sending_peers():
    sending_peers_list = set()
    for peer in peers:
        sending_peers_list.add(peer)
    return sending_peers_list


def block_props_json_to_class(block_props_json_):
    if block_props_json_ == "None":
        return None

    if type(block_props_json_) is str:
        block_props_json = json.loads(block_props_json_)
    else:
        block_props_json = block_props_json_

    qc = []
    for i in range(0, len(block_props_json["block"]["previous_qc"])):
        qc.append([block_props_json["block"]["previous_qc"][i][0],
                   base64.b64decode(block_props_json["block"]["previous_qc"][i][1]['py/b64'])])

    new_block = Block(block_props_json["block"]["height"], block_props_json["block"]["transactions"],
                      block_props_json["block"]["timestamp"], block_props_json["block"]["previous_hash"],
                      qc, block_props_json["block"]["nonce"])

    block_props = BlockProps(new_block, block_props_json["parent_idx"])
    block_props.votes = block_props_json["votes"]
    block_props.certified = block_props_json["certified"]
    block_props.committed = block_props_json["committed"]
    block_props.cert_count = block_props_json["cert_count"]
    block_props.comm_count = block_props_json["comm_count"]

    return block_props


def thread(function_name, variables):
    if function_name == "propagate_block_props":
        if len(variables) == 1:
            t1 = threading.Thread(target=propagate_block_props, args=(variables["block_props"],))
            t1.start()
    if function_name == "propagate_vote":
        if len(variables) == 2:
            t1 = threading.Thread(target=propagate_vote, args=(variables["coded_vote"], variables["signature"],))
            t1.start()
    if function_name == "propagate_tx":
        if len(variables) == 1:
            t1 = threading.Thread(target=propagate_tx, args=(variables["tx_data"],))
            t1.start()


def compute_hash(block):
    # block_string = jsonpickle.encode(block)
    # return sha256(block_string.encode()).hexdigest()
    return str(hash(block.timestamp))


# Uncomment this line if you want to specify the port number in the code
# app.run(debug=True, port=8000)

port = sys.argv[-1]

if port == '9000':
    global peers
    peers = set()
    peer_base = "http://127.0.0.1:8000/"
    peers.add(peer_base)
    on = True
    j = 0
    while on:
        j += 1
        rand_int = random.randint(0, 1) / 20
        time.sleep(rand_int)
        new_transaction()
        print("tx " + str(j) + " is sent")

# the node's copy of blockchain
blockchain = Blockchain()
blockchain.create_genesis_block()

# the address to other participating members of the network
peers = set()
keys = set()
global retry_request
retry_request = 2
global self_private_key
self_private_key = key_gen()
global self_public_key
self_public_key = self_private_key.public_key()
keys.add(self_public_key)
global number_of_block_transactions
number_of_block_transactions = 20
global sec
sec = 5
global start_time
start_time = time.time()


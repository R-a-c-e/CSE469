#!/usr/bin/env python3
import struct
import time
import os
import datetime
import sys
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

#the blockchain will consist of blocks, stored sequentially in binary format in a file. This means there is no
#linked list or other data structures directly connecting one block to another; it is implicit through their
#ordering in the file, double checked with 

CONST_BCHOC_FILEPATH = ""
NULL = b'\x00'
KEY = b'0123456789abcdef0123456789abcdef'
CIPHER = AES.new(KEY, AES.MODE_ECB)

class Block():
    
    format_string = '32s d 32s 32s 12s 12s 12s I'
    block_header_size = struct.calcsize(format_string)
    

    CONST_INITIAL = "INITIAL"
    CONST_CHECKEDIN = "CHECKEDIN"
    CONST_CHECKEDOUT = "CHECKEDOUT"
    CONST_DISPOSED = "DISPOSED"
    CONST_DESTROYED = "DESTROYED"
    CONST_RELEASED = "RELEASED"

    CONST_POLICE = "Police"
    CONST_LAWYER = "Lawyer"
    CONST_ANALYST = "Analyst"
    CONST_EXECUTIVE = "Executive"

    #assumes checks for proper input, truncaton of input, encryption of fields, etc happen after accpeting user input
    def __init__(self, parent_sha256, timestamp, case_id, item_id, state, creator, owner, data_length, data):
        
        self.parent_sha256 = parent_sha256

        if timestamp==None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        self.case_id = case_id
        self.item_id = item_id

        #block can be created for adding an evidence item, checking it out, etc., so block creation could have multiple states
        self.state = state

        self.creator = creator
 
        self.owner = owner

        self.data_length = data_length
        self.data = data
    
    def __str__(self):
        return f"Block(parent_sha256={self.parent_sha256}, timestamp={self.timestamp}, case_id={self.case_id}, item_id={self.item_id}, state={self.state}, creator={self.creator}, owner={self.owner}, data_length={self.data_length}, data={self.data})"
    
    def pack_block(self):
        return struct.pack(Block.format_string, self.parent_sha256, self.timestamp, self.case_id, self.item_id, self.state, self.creator, self.owner, self.data_length) + self.data
    
    def unpack_block(block_byteform):
        parent_sha256, timestamp, case_id, item_id, state, creator, owner, data_length = struct.unpack(Block.format_string, block_byteform)
        return Block(parent_sha256=parent_sha256.decode(), timestamp=timestamp, case_id=case_id, item_id=item_id, state=state.decode(), creator=creator.decode(), owner=owner.decode(), data_length=data_length, data=b'')

def init():
    if os.path.exists(CONST_BCHOC_FILEPATH):
        print("Blockchain already exists.")
        return
    # Create initial block
    initial_block = Block(NULL, None, NULL, NULL, b'INITIAL', NULL, NULL, 14, b'Initial Block')
    initial_block = initial_block.pack_block()

    # Write initial block to file
    with open(CONST_BCHOC_FILEPATH, 'wb') as file:
        file.write(initial_block)
    print("Blockchain initialized.")

def add_evidence(case_id, item_ids, creator_password, creator):
    # Check if blockchain file exists
    if not os.path.exists(CONST_BCHOC_FILEPATH):
        print("Blockchain doesn't exist. Initialize the blockchain first.")
        return
    
    # Validate creator's password (Not implemented in this example)
    # Validate uniqueness of item IDs (Not implemented in this example)
    
    # Open blockchain file in append mode
    with open(CONST_BCHOC_FILEPATH, 'ab') as file:
        for item_id in item_ids:
            if not unique_evidence_id(item_id):
                print(f"Evidence item ID {item_id} is not unique. Skipping.")
                continue
            # Create new block for each item
            encrypted_case_id = encrypt_data(struct.pack('32s', case_id.encode()))
            encrypted_item_id = encrypt_data(struct.pack('32s', str(item_id).encode()))
            new_block = Block(NULL, None, encrypted_case_id, encrypted_item_id, b'CHECKEDIN', creator.encode(), Block.CONST_POLICE.encode(), 0, b'')
            packed_block = new_block.pack_block()
            # Write block to file
            file.write(packed_block)
            print(f"Evidence item {item_id} added to the blockchain.")

# Function to encrypt data using AES ECB mode
def encrypt_data(data):
    ciphertext = CIPHER.encrypt(pad(data, AES.block_size))
    return ciphertext

def decrypt_data(ciphertext):
    plaintext = CIPHER.decrypt(ciphertext)
    return plaintext.strip(b'x\00')

def unique_evidence_id(item_id):
    with open(CONST_BCHOC_FILEPATH, 'rb') as file:
        while True:
            # Read a block from the file
            block_data = file.read(Block.block_header_size)
            if not block_data:
                break  # Reached end of file
            # Unpack the block data
            block = Block.unpack_block(block_data)
            file.read(block.data_length - 1)
            # Check if item_id matches any existing item_id in the blockchain
            if block.state.encode().strip(b'x\00') != b'INITIAL':
                block_id = decrypt_data(block.item_id)
                if block_id.decode() == str(item_id):
                    return False  # item_id is not unique
    return True  # item_id is unique
if __name__=="__main__":

    if "BCHOC_FILE_PATH" in os.environ:
        CONST_BCHOC_FILEPATH = os.environ["BCHOC_FILE_PATH"]
    else:
        CONST_BCHOC_FILEPATH = "blockchain.bin"

    if sys.argv[1] == 'init':
        init()
    elif sys.argv[1] == 'add':
        case_id_index = sys.argv.index('-c') + 1
        case_id = sys.argv[case_id_index]
        item_id_index = sys.argv.index('-i') + 1
        creator_index = sys.argv.index('-c', case_id_index + 1) + 1
        item_ids = [int(sys.argv[i]) for i in range(item_id_index, creator_index - 1)]
        creator = sys.argv[creator_index]
        password_index = sys.argv.index('-p') + 1
        creator_password = sys.argv[password_index]
        add_evidence(case_id, item_ids, creator_password, creator)

#!/usr/bin/env python3
import os
import sys
import struct
import uuid
import time
from Crypto.Cipher import AES

# Constants
BLOCK_STRUCT_FORMAT = "32s d 32s 32s 12s 12s 12s I"
INITIAL_STATE = b'INITIAL'
NONE = b'\x00'
BLOCK_SIZE = struct.calcsize(BLOCK_STRUCT_FORMAT)
ENCRYPTION_KEY = b'my_secret_key' + b'\x00' * (16 - len(b'my_secret_key'))

# Function to initialize the blockchain if it doesn't exist
def init():
    if os.path.exists("test.dat"):
        print("Blockchain already exists.")
        sys.exit(1)
    
    # Create initial block
    initial_block = create_initial_block()

    # Write initial block to file
    with open("test.dat", 'wb') as file:
        file.write(initial_block)

    print("Blockchain initialized.")

# Function to create the initial block
def create_initial_block():
    previous_hash = b'\x00' * 32  # Placeholder for previous hash
    timestamp = time.time()
    case_id = NONE
    item_id = NONE
    state = INITIAL_STATE
    creator = NONE
    owner = NONE
    data_length = 14
    data = b'Initial block'

    # Encrypt case_id and item_id
    encrypted_case_id = encrypt_aes_ecb(ENCRYPTION_KEY, case_id) if case_id else None
    encrypted_item_id = encrypt_aes_ecb(ENCRYPTION_KEY, item_id) if item_id else None

    # Pack block data
    block_data = struct.pack(BLOCK_STRUCT_FORMAT, previous_hash, timestamp, encrypted_case_id, encrypted_item_id, state, creator, owner, data_length) + data

    return block_data

# Function to encrypt data using AES ECB mode
def encrypt_aes_ecb(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad_data(data))

# Function to pad data to be encrypted
def pad_data(data):
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def add(case_id, item_ids, creator, password):
    # Check if blockchain file exists
    if not os.path.exists("test.dat"):
        print("Blockchain file not found.")
        sys.exit(1)

    # Encrypt case_id and item_ids
    encrypted_case_id = encrypt_aes_ecb(ENCRYPTION_KEY, case_id.encode('utf-8'))
    encrypted_item_ids = [encrypt_aes_ecb(ENCRYPTION_KEY, str(item_id).encode('utf-8')) for item_id in item_ids]

    # Read the previous hash from the last block
    with open("test.dat", 'rb') as file:
        file.seek(-BLOCK_SIZE, os.SEEK_END)
        previous_block = file.read()

    # Generate timestamp
    timestamp = time.time()

    # Create new block data
    state = "CHECKEDIN"
    creator_bytes = creator.encode('utf-8')
    owner_bytes = creator_bytes  # For now, owner is the creator
    data_length = 0  # Placeholder for data length
    data = b""  # Placeholder for data

    # Pack block data
    new_block_data = struct.pack(BLOCK_STRUCT_FORMAT, previous_block[:32], timestamp, encrypted_case_id, b"", state.encode('utf-8'), creator_bytes, owner_bytes, data_length) + data

    # Append new block to blockchain file
    with open("test.dat", 'ab') as file:
        file.write(new_block_data)

    print("Item(s) added to the blockchain.")

# Main function
def main():
    if sys.argv[1] == 'init':
        init()
    
    elif sys.argv[1] == 'add':
        case_id_index = sys.argv.index('-c') + 1
        case_id = sys.argv[case_id_index]
        item_id_indices = [i + 1 for i, arg in enumerate(sys.argv) if arg == '-i']
        item_ids = [int(sys.argv[i]) for i in item_id_indices]
        creator_index = sys.argv.index('-c') + 1
        creator = sys.argv[creator_index]
        password_index = sys.argv.index('-p') + 1
        password = sys.argv[password_index]

        # Add item(s) to the blockchain
        add(case_id, item_ids, creator, password)
    

if __name__ == "__main__":
    main()
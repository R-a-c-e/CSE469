import os
import sys
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import time
import uuid

# Struct format string for packing and unpacking block fields
BLOCK_STRUCT_FORMAT = "32s d 32s 32s 12s 12s 12s I"

# AES ECB mode encryption function
def encrypt_aes_ecb(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

# AES ECB mode decryption function
def decrypt_aes_ecb(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode()

# Function to calculate block hash
def calculate_block_hash(previous_hash, timestamp, case_id, item_id, state, creator, owner, data_length, data):
    block_data = struct.pack(BLOCK_STRUCT_FORMAT, previous_hash, timestamp, case_id, item_id, state, creator, owner, data_length) + data
    return hashlib.sha256(block_data).digest()

# Function to create initial block
def create_initial_block():
    timestamp = int(time.time())
    case_id = uuid.uuid4().hex
    item_id = None
    previous_hash = None
    state = "INITIAL"
    creator = None
    owner = None
    data_length = 14
    data = b"Initial block"
    return (previous_hash, timestamp, case_id, item_id, state, creator, owner, data_length, data)

# Function to add a new block
def add_block(previous_hash, timestamp, case_id, item_id, state, creator, owner, data_length, data, key):
    # Encrypt case_id and item_id
    encrypted_case_id = encrypt_aes_ecb(key, case_id)
    encrypted_item_id = encrypt_aes_ecb(key, str(item_id))

    # Calculate block hash
    block_hash = calculate_block_hash(previous_hash, timestamp, encrypted_case_id, encrypted_item_id, state, creator, owner, data_length, data)

    # Write block to file
    with open("test.dat", "ab") as file:
        block = struct.pack(BLOCK_STRUCT_FORMAT, block_hash, timestamp, encrypted_case_id, encrypted_item_id, state, creator, owner, data_length) + data
        file.write(block)
    print("done")

# Function to retrieve blocks from file
def retrieve_blocks():
    blocks = []
    try:
        with open("test.dat", "rb") as file:
            while True:
                block_data = file.read(struct.calcsize(BLOCK_STRUCT_FORMAT))
                if not block_data:
                    break
                block = struct.unpack(BLOCK_STRUCT_FORMAT, block_data)
                blocks.append(block)
    except FileNotFoundError:
        pass
    return blocks

# Function to handle the 'bchoc add' command
def handle_add_command(case_id, item_ids, creator_password, key):
    # Check if case_id is valid UUID

    # Check if item_ids are integers
    for item_id in item_ids:
        if not isinstance(item_id, int):
            sys.exit(1)

    # Encrypt creator_password
    encrypted_creator_password = encrypt_aes_ecb(key, creator_password)
    # Add each item_id to the blockchain
    for item_id in item_ids:
        timestamp = int(time.time())
        state = "CHECKEDIN"
        data = b""  # No additional data for now
        previous_hash = None  # Get last block's hash from blockchain file
        owner = None  # Initially no owner

        # Add block to the blockchain
        add_block(previous_hash, timestamp, case_id, item_id, state, encrypted_creator_password, owner, len(data), data, key)
        
# Other command handlers (checkout, checkin, show cases, show items, show history, remove, init, verify) to be implemented similarly...
def parse_add_command_args(args):
    if len(args) < 8:
        print("Insufficient arguments for 'add' command.")
        sys.exit(1)
    if '-p' not in args:
        print("Password flag '-p' is missing.")
        sys.exit(1)

    if '-c' not in args:
        print("Case ID flag '-c' is missing.")
        sys.exit(1)

    if '-i' not in args:
        print("Item ID flag '-i' is missing.")
        sys.exit(1)

    if len(args) < 8:
        print("Insufficient arguments for 'add' command.")
        sys.exit(1)

    case_id_index = args.index('-c')
    item_ids = []

    for i in range(len(args)):
        if args[i] == '-i':
            item_ids.append(int(args[i+1]))

    creator_password = args[args.index('-p') + 1]

    case_id = args[case_id_index + 1]
    
    return case_id, item_ids, creator_password

# Main function
def main():

    # Check if blockchain file exists, if not create initial block
    if not os.path.isfile("test.dat"):
        initial_block_data = create_initial_block()
        with open("test.dat", "wb") as file:
            file.write(struct.pack(BLOCK_STRUCT_FORMAT, *initial_block_data))

    # Retrieve blocks from file
    blocks = retrieve_blocks()
    key = b'my_secret_key12345'
    if len(key) < 16:
        key = key.ljust(16, b'\0')
    elif len(key) > 16:
        key = key[:16]
    # Handle commands based on user input...
    command = sys.argv[1]
    if command == "add":
        case_id, item_ids, creator_password = parse_add_command_args(sys.argv)
        handle_add_command(case_id, item_ids, creator_password, key)

if __name__ == "__main__":
    main()
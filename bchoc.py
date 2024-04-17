#!/usr/bin/env python3
import struct
import time
import os
import sys
import uuid
from Crypto.Cipher import AES
import argparse
from datetime import datetime

#the blockchain will consist of blocks, stored sequentially in binary format in a file. This means there is no
#linked list or other data structures directly connecting one block to another; it is implicit through their
#ordering in the file, double checked with 

CONST_BCHOC_FILEPATH = ""
NULL = b'\x00'
KEY =  b'R0chLi4uLi4uLi4=' 
CIPHER = AES.new(KEY, AES.MODE_ECB)

class Block():
    
    format_string = '<32s d 32s 32s 12s 12s 12s I'
    block_header_size = struct.calcsize(format_string)
    

    CONST_INITIAL = "INITIAL"
    CONST_CHECKEDIN = "CHECKEDIN"
    CONST_CHECKEDOUT = "CHECKEDOUT"
    CONST_DISPOSED = "DISPOSED"
    CONST_DESTROYED = "DESTROYED"
    CONST_RELEASED = "RELEASED"

    #assumes checks for proper input, truncaton of input, encryption of fields, etc happen after accpeting user input
    def __init__(self, parent_sha256, timestamp, case_id, item_id, state, creator, owner, data_length, data):
        
        self.parent_sha256 = parent_sha256

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
        try:
            parent_sha256, timestamp, case_id, item_id, state, creator, owner, data_length = struct.unpack(Block.format_string, block_byteform)
            return Block(parent_sha256=parent_sha256, timestamp=timestamp, case_id=case_id, item_id=item_id, state=state, creator=creator, owner=owner, data_length=data_length, data=b'')
        except struct.error as e:
            print("Error occured:", e)
            sys.exit(1)

def match_password(password):
    # Define predefined passwords
    predefined_passwords = {
        "P80P": "POLICE",
        "L76L": "LAWYER",
        "A65A": "ANALYST",
        "E69E": "EXECUTIVE",
        "C67C": "CREATOR"
    }

    # Check if the provided password matches any predefined password
    return predefined_passwords.get(password, None)

def valid_reason(reason):
    predefined_reason = {
        "DISPOSED": 1,
        "DESTROYED": 1,
        "RELEASED": 1
    }
   
    return predefined_reason.get(reason, None)

def init():
    try:
        with open(CONST_BCHOC_FILEPATH, 'rb') as file:
            block_data = file.read(144)
            block = Block.unpack_block(block_data)
            if block.state.strip(b'\x00') == b'INITIAL':
                print("File Found w/ INITIAL")
            else:
                print("No INITIAL")
                sys.exit(1)
    except FileNotFoundError:
        # Create initial block
        initial_block = Block(NULL, 0, b"0"*32, b"0"*32, b'INITIAL', NULL, NULL, 14, b'Initial block\x00')
        initial_block = initial_block.pack_block()

        # Write initial block to file
        with open(CONST_BCHOC_FILEPATH, 'wb') as file:
            file.write(initial_block)
        with open(CONST_BCHOC_FILEPATH, 'rb') as file:
            data = file.read(144)
            initial_block = Block.unpack_block(data)
            print(initial_block.parent_sha256)
            print(initial_block.timestamp)
            print(initial_block.case_id)
            print(initial_block.item_id)
            print(initial_block.state)
            print(initial_block.creator)
            print(initial_block.owner)
            print(initial_block.data_length)
            print(file.read(initial_block.data_length))

def add_evidence(case_id, item_ids, password, creator):
    # Check if blockchain file exists
    if not os.path.exists(CONST_BCHOC_FILEPATH):
        print("Blockchain doesn't exist. Initialize the blockchain first.")
        init()
        return
    
    # Validate creator's password (Not implemented in this example)
    # Validate uniqueness of item IDs (Not implemented in this example)
    
    # Open blockchain file in append mode
    with open(CONST_BCHOC_FILEPATH, 'ab') as file:
        for item_id in item_ids:
            if not unique_evidence_id(item_id):
                print(f"Evidence item ID {item_id} is not unique. Skipping.")
                sys.exit(1)
            # Create new block for each item
            owner = match_password(password)
            if owner == "CREATOR":
                owner = NULL
            elif owner == None:
                sys.exit(1)
            item = uuid.UUID(case_id)
            bytes_data = item.bytes
            encrypted_case_id = encrypt_data(bytes_data)
            bytes_data = int(item_id).to_bytes(4, byteorder='big')
            encrypted_item_id = encrypt_data(bytes_data)
            encrypted_item_id = struct.pack('32s', encrypted_item_id)
            encrypted_case_id = struct.pack('32s', encrypted_case_id)
            new_block = Block(NULL, time.time(), encrypted_case_id, encrypted_item_id, b'CHECKEDIN', creator.encode(), owner, 0, b'')
            packed_block = new_block.pack_block()
            # Write block to file
            file.write(packed_block)
            print(f"Evidence item {item_id} added to the blockchain.")

# Function to encrypt data using AES ECB mode
def encrypt_data(data):
    cipher = data.hex().zfill(32)
    cipher = CIPHER.encrypt(bytes.fromhex(cipher))
    cipher = cipher.hex()
    ciphertext = cipher.encode()
    return ciphertext

def decrypt_data(ciphertext):
    cipher = ciphertext.decode()
    cipher = bytes.fromhex(cipher)
    plaintext = CIPHER.decrypt(cipher)
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
            file.read(block.data_length)
            # Check if item_id matches any existing item_id in the blockchain
            if block.state.strip(b'x\00') != b'INITIAL':
                block_id = decrypt_data(block.item_id)
                block_id = int.from_bytes(block_id, byteorder='big')
                if str(block_id) == str(item_id):
                    return False  # item_id is not unique
    return True  # item_id is unique

def checkin(item_id, password):
    status = None
    block_to_add = None
    data_to_add = None
    with open(CONST_BCHOC_FILEPATH, 'r+b') as file:
        while True:
            # Read a block from the file
            block_data = file.read(Block.block_header_size)
            if not block_data:
                if status == None:
                    print("No Block Found")
                    sys.exit(1)
                else:
                    if status.decode().strip('\x00') == "CHECKEDOUT":
                        file.seek(0,2)
                        block = block_to_add
                        block.state = struct.pack('12s', Block.CONST_CHECKEDIN.encode())
                        block.owner = struct.pack('12s', match_password(password).encode())
                        file.write(block.pack_block() + data_to_add)
                        print("Block Checkedin")
                        break  # Reached end of file
                    else:
                        print("Can NOT Checkin")
                        sys.exit(1)
            # Unpack the block data
            block = Block.unpack_block(block_data)
            data = file.read(block.data_length)
            # Check if item_id matches any existing item_id in the blockchain
            block_id = decrypt_data(block.item_id)
            block_id = int.from_bytes(block_id, byteorder='big')
            if str(block_id) == str(item_id):
                if match_password(password) != None:
                    status = block.state
                    block_to_add = block
                    data_to_add = data

def checkout(item_id, password):
    status = None
    block_to_add = None
    data_to_add = None
    with open(CONST_BCHOC_FILEPATH, 'r+b') as file:
        while True:
            # Read a block from the file
            block_data = file.read(Block.block_header_size)
            if not block_data:
                if status == None:
                    print("No Block Found")
                    sys.exit(1)
                else:
                    if status.decode().strip('\x00') == "CHECKEDIN":
                        file.seek(0,2)
                        block = block_to_add
                        block.state = struct.pack('12s', Block.CONST_CHECKEDOUT.encode())
                        block.owner = struct.pack('12s', match_password(password).encode())
                        file.write(block.pack_block() + data_to_add)
                        print("Block Checkedout")
                        break  # Reached end of file
                    else:
                        print("Can NOT Checkout")
                        sys.exit(1)
            # Unpack the block data
            block = Block.unpack_block(block_data)
            data = file.read(block.data_length)
            # Check if item_id matches any existing item_id in the blockchain
            block_id = decrypt_data(block.item_id)
            block_id = int.from_bytes(block_id, byteorder='big')
            if str(block_id) == str(item_id):
                if match_password(password) != None:
                    status = block.state
                    block_to_add = block
                    data_to_add = data

def remove(item_id, password, reason):
    status = None
    block_to_remove = None
    data_to_remove = None
    with open(CONST_BCHOC_FILEPATH, 'r+b') as file:
        while True:
            # Read a block from the file
            block_data = file.read(Block.block_header_size)
            if not block_data:
                if status == None:
                    print("Can Not Remove")
                    sys.exit(1)
                else:
                    if status.decode().strip('\x00') == "CHECKEDIN":
                        file.seek(0,2)
                        block = block_to_remove
                        block.state = struct.pack('12s', reason.encode())
                        file.write(block.pack_block() + data_to_remove)
                        print("Block", reason)
                        break  # Reached end of file
                    else:
                        print("Can NOT Remove")
                        sys.exit(1)
            # Unpack the block data
            block = Block.unpack_block(block_data)
            data = file.read(block.data_length)
            # Check if item_id matches any existing item_id in the blockchain
            block_id = decrypt_data(block.item_id)
            block_id = int.from_bytes(block_id, byteorder='big')
            if str(block_id) == str(item_id):
                if match_password(password) == "CREATOR":
                    status = block.state
                    block_to_remove = block
                    data_to_remove = data

def show_history(case_id, item_id, num_entries, reverse, password):
    history_entries = []   
    with open(CONST_BCHOC_FILEPATH, 'rb') as file:
        while True and reverse == None and password != None:
            # Read a block from the file
            block_data = file.read(Block.block_header_size)
            if not block_data:
                break
            # Unpack the block data
            block = Block.unpack_block(block_data)
            data = file.read(block.data_length)
            # Check if item_id matches any existing item_id in the blockchain
            block_id = decrypt_data(block.item_id)
            block_id_data = int.from_bytes(block_id, byteorder='big')
            block_case = decrypt_data(block.case_id)
            block_case_data = uuid.UUID(bytes=block_case)
            if str(block_id_data) == str(item_id) or str(block_case_data) == str(case_id):
                if match_password(password) != None:
                    datetime_obj = datetime.utcfromtimestamp(block.timestamp)
                    formatted_time_str = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    history_entries.append({'caseid': str(block_case_data), 'evidence_id' : str(block_id_data), 'state': block.state.decode().strip('\x00'), 'timestamp' : formatted_time_str})
            elif num_entries != None and match_password(password) != None:
                for n in range(int(num_entries)):
                    if not block_data:
                        break
                    if block.state.strip(b'x\00') != b'INITIAL':
                        block_id = decrypt_data(block.item_id)
                        block_id_data = int.from_bytes(block_id, byteorder='big')
                        block_case = decrypt_data(block.case_id)
                        block_case_data = uuid.UUID(bytes=block_case)
                        datetime_obj = datetime.utcfromtimestamp(block.timestamp)
                        formatted_time_str = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        history_entries.append({'caseid': str(block_case_data), 'evidence_id' : str(block_id_data), 'state': block.state.decode().strip('\x00'), 'timestamp' : formatted_time_str})
                    else:
                        datetime_obj = datetime.utcfromtimestamp(time.time())
                        formatted_time_str = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        history_entries.append({'caseid': b'00000000-0000-0000-0000-000000000000'.decode(), 'evidence_id' : b'0'.decode(), 'state': block.state.decode().strip('\x00'), 'timestamp' : formatted_time_str})
                    block_data = file.read(Block.block_header_size)
                    try:
                        block = Block.unpack_block(block_data)
                    except:
                        break
                    data = file.read(block.data_length)
                break
        if reverse == 1:
            file.seek(0,2)
            end = file.tell()
            size_in_bytes = os.path.getsize(CONST_BCHOC_FILEPATH)
            num_blocks = (size_in_bytes - 158) / Block.block_header_size
            for n in range(int(num_blocks)):
                file.seek(end - (n + 1) * Block.block_header_size)
                block_data = file.read(Block.block_header_size)
                block = Block.unpack_block(block_data)
                # Check if item_id matches any existing item_id in the blockchain
                block_id = decrypt_data(block.item_id)
                block_id_data = int.from_bytes(block_id, byteorder='big')
                block_case = decrypt_data(block.case_id)
                block_case_data = uuid.UUID(bytes=block_case)
                datetime_obj = datetime.utcfromtimestamp(block.timestamp)
                formatted_time_str = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                if item_id == None:
                    history_entries.append({'caseid': str(block_case_data), 'evidence_id' : str(block_id_data), 'state': block.state.decode().strip('\x00'), 'timestamp' : formatted_time_str})
                elif str(block_id_data) == str(item_id):
                    history_entries.append({'caseid': str(block_case_data), 'evidence_id' : str(block_id_data), 'state': block.state.decode().strip('\x00'), 'timestamp' : formatted_time_str})
            datetime_obj = datetime.utcfromtimestamp(time.time())
            formatted_time_str = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            if item_id == None:
                history_entries.append({'caseid': b'00000000-0000-0000-0000-000000000000'.decode(), 'evidence_id' : b'0'.decode(), 'state': Block.CONST_INITIAL, 'timestamp' : formatted_time_str})
        elif password == None:
            while True:
                block_data = file.read(Block.block_header_size)
                if not block_data:
                    break
                # Unpack the block data
                block = Block.unpack_block(block_data)
                data = file.read(block.data_length)
                # Check if item_id matches any existing item_id in the blockchain
                block_id = decrypt_data(block.item_id)
                block_id_data = int.from_bytes(block_id, byteorder='big')
                block_case = decrypt_data(block.case_id)
                block_case_data = uuid.UUID(bytes=block_case)
                if str(block_id_data) == str(item_id) or str(block_case_data) == str(case_id):
                    datetime_obj = datetime.utcfromtimestamp(block.timestamp)
                    formatted_time_str = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    history_entries.append({'caseid': block.case_id.decode(), 'evidence_id' : block.item_id.decode(), 'state': block.state.decode().strip('\x00'), 'timestamp' : formatted_time_str})
    for entry in history_entries:
        print("Case:", entry['caseid'])
        print("Item:", entry['evidence_id'])
        print("Action:", entry['state'])
        print("Time:", entry['timestamp'])
        print()



if __name__=="__main__":
    if 'BCHOC_FILE_PATH' in os.environ:
        CONST_BCHOC_FILEPATH = os.environ['BCHOC_FILE_PATH']
    else:
        CONST_BCHOC_FILEPATH = "blockchain.bin"

    if sys.argv[1] != 'show' and sys.argv[1] != 'init':
        parser = argparse.ArgumentParser(description="Blockchain Chain of Custody (BCHOC) Tool")
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        add_parser = subparsers.add_parser("add", help="Add a new evidence item to the blockchain")
        add_parser.add_argument("-c", "--case-id", required=True, help="Case identifier")
        add_parser.add_argument("-i", "--item-id", action="append", required=True, help="Evidence item identifier")
        add_parser.add_argument("-g", "--creator", required=True, help="Creator")
        add_parser.add_argument("-p", "--password", required=True, help="Creator's password")

        # Define the parser for the 'checkin' command
        checkin_parser = subparsers.add_parser("checkin", help="Check in an evidence item to the blockchain")
        checkin_parser.add_argument("-i", "--item-id", required=True, help="Evidence item identifier")
        checkin_parser.add_argument("-p", "--password", required=True, help="Creator's password")

        # Define the parser for the 'checkin' command
        checkout_parser = subparsers.add_parser("checkout", help="Check out an evidence item to the blockchain")
        checkout_parser.add_argument("-i", "--item-id", required=True, help="Evidence item identifier")
        checkout_parser.add_argument("-p", "--password", required=True, help="Creator's password")

        remove_parser = subparsers.add_parser("remove", help="Remove an item from the blockchain")
        remove_parser.add_argument("-i", "--item-id", required=True, help="Item identifier")
        remove_parser.add_argument("-y", "--why", dest="reason", required=True, help="Reason for removal")
        remove_parser.add_argument("-p", "--password", required=True, help="Creator's password")

        args = parser.parse_args()

    if sys.argv[1] == 'init':
        if len(sys.argv) > 2: 
            print("Improper input")
            sys.exit(1)
        else:
            init()
    elif sys.argv[1] == 'add':
        add_evidence(args.case_id, args.item_id, args.password, args.creator)
    elif sys.argv[1] == 'checkin':
        checkin(args.item_id, args.password)
    elif sys.argv[1] == 'checkout':
        checkout(args.item_id, args.password)
    elif sys.argv[1] == 'remove':
        if valid_reason(args.reason) == 1:
            remove(args.item_id, args.password, args.reason)
        else:
            print("Invalid Reason")
            sys.exit(1)
    elif sys.argv[1] == 'show' and sys.argv[2] == 'history':
        command_args = sys.argv
        try:
            case_index = command_args.index('-c')
            case_id = command_args[case_index + 1]
        except ValueError:
            case_id = None
        try:
            item_index = command_args.index('-i')
            item_id = command_args[item_index + 1]
        except ValueError:
            item_id = None
        try:
            num_index = command_args.index('-n')
            num_id = command_args[num_index + 1]
        except ValueError:
            num_id = None
        try:
            rev_index = command_args.index('-r')
            reverse = 1
        except ValueError:
            try:
                rev_index = command_args.index('--reverse')
                reverse = 1
            except:
                reverse = None
        try:
            password_index = command_args.index('-p')
            password = command_args[password_index + 1]
        except ValueError:
            password = None
        show_history(case_id, item_id, num_id, reverse, password)

import struct
import time
import os
import datetime

#the blockchain will consist of blocks, stored sequentially in binary format in a file. This means there is no
#linked list or other data structures directly connecting one block to another; it is implicit through their
#ordering in the file, double checked with 

CONST_BCHOC_FILEPATH = ""

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
    def __init__(self, parent_sha256, case_id, item_id, state, creator, owner, data_length, data="", timestamp=None):
        
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
        return struct.pack(Block.format_string, self.parent_sha256.encode(), self.timestamp, self.case_id.encode(), self.item_id.encode(), self.state.encode(), self.creator.encode(), self.owner.encode(), self.data_length)
    
    def unpack_block(block_byteform):
        parent_sha256, timestamp, case_id, item_id, state, creator, owner, data_length = struct.unpack(Block.format_string, block_byteform)
        return Block(parent_sha256=parent_sha256.decode(), case_id=case_id.decode(), item_id=item_id.decode(), state=state.decode(), creator=creator.decode(), owner=owner.decode(), data_length=data_length, timestamp=timestamp)



if __name__=="__main__":

    if "BCHOC_FILE_PATH" in os.environ:
        CONST_BCHOC_FILEPATH = os.environ["BCHOC_FILE_PATH"]
    else:
        CONST_BCHOC_FILEPATH = "blockchain.bin"

    # #quick tests to check my work
    # block = Block("lalala","encrypted_here","encrypted_here",Block.CONST_INITIAL,"austin",Block.CONST_POLICE,0)
    # print(block)
    # print("unix time:", block.timestamp)
    # block_bin = block.pack_block()
    # print(len(block_bin), " vs ", Block.block_header_size)
    # block = Block.unpack_block(block_byteform=block_bin)
    # print(block)

    while True:
        #accept, process, and direct user requests to appropriate calls here
        pass
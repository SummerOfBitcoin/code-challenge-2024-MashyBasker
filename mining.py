import json
from verify import compact_size, hash256
import hashlib
import struct
import os
import time

def create_tx_id(tx_json):
    txid = ""
    tx_data = json.loads(tx_json)
    txid += struct.pack('<I', tx_data['version']).hex()
    txid += compact_size(len(tx_data['vin'])).hex()
    for vin in tx_data['vin']:
        txid += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
        txid += struct.pack('<I', vin['vout']).hex()
        txid += compact_size(len(vin['scriptsig'])//2).hex()
        txid += vin['scriptsig']
        txid += struct.pack('<I', vin['sequence']).hex()
    txid += compact_size(len(tx_data['vout'])).hex()
    for vout in tx_data['vout']:
        txid += struct.pack('<Q', int(vout['value'])).hex()
        txid += compact_size(len(vout['scriptpubkey'])//2).hex()
        txid += vout['scriptpubkey']
    txid += struct.pack('<I', tx_data['locktime']).hex()
    return hash256(bytes.fromhex(txid))[::-1]

def hash2(a, b):
    a1 = bytes.fromhex(a)[::-1]
    b1 = bytes.fromhex(b)[::-1]
    h = hashlib.sha256(hashlib.sha256(a1 + b1).digest()).digest()
    return h[::-1].hex()

def merkle(hashlist):
    if len(hashlist) == 1:
        return hashlist[0]
    new_hashlist = []
    for i in range(0, len(hashlist)-1, 2):
        new_hashlist.append(hash2(hashlist[i], hashlist[i+1]))
    if len(hashlist) % 2 == 1:
        new_hashlist.append(hash2(hashlist[-1], hashlist[-1]))
    return merkle(new_hashlist)

def calculate_coinbase():
    coinbase = ""
    version = "01000000"
    marker = "00"
    flag = "01"
    input_count = "01"
    txid = (b'\x00'*32).hex()
    vout = "ffffffff"
    scirptsigsize = "03000000184d696e656420627920416e74506f6f6c373946205b8160a4"
    scirptsigsize = "1d"
    sequence = "ffffffff"
    outputcount = "02"
    coinbase = version + marker + flag + input_count + txid + vout + scirptsigsize + sequence + outputcount
    
    coinbase += "f595814a00000000" + "19" + "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac" # vout 1
    coinbase += "0000000000000000" + "26" + "6a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db" # vout 2
    
    # add witness
    coinbase += "01" + "20" + "0000000000000000000000000000000000000000000000000000000000000000"
    coinbase += "00000000" # add locktime
    return coinbase
        
def txid_list():
    txid_list = []
    for file in os.listdir("./verified"):
        f = open("./verified/"+file)
        tx_data = json.load(f)
        txid_list.append(create_tx_id(json.dumps(tx_data)).hex())
    return txid_list
    
def blockheader(txidlst):
    ver = bytes.fromhex("00000020")
    prevblock = "0000000000000000000000000000000000000000000000000000000000000000"
    merkle_root = merkle(txidlst)
    target_bits = 0x1f00ffff
    exp = target_bits >> 24
    mant = target_bits & 0xffffff
    target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
    target_str = bytes.fromhex(target_hexstr)
    nonce = 0

    while nonce < 0x100000000:
        header = ver + bytes.fromhex(prevblock)[::-1] +\
            bytes.fromhex(merkle_root)[::-1] + struct.pack("<LLL", int(hex(int(time.time())),16), target_bits, nonce)
        hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        # print(nonce, (hash[::-1]).hex())
        if hash[::-1] < target_str:
            return header.hex()
        nonce += 1
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
        txid += struct.pack('<Q', vout['value']).hex()
        txid += compact_size(len(vout['scriptpubkey'])//2).hex()
        txid += vout['scriptpubkey']
    txid += struct.pack('<I', int(tx_data['locktime'])).hex()
    txid_hash = hash256(bytes.fromhex(txid))
    return txid_hash[::-1].hex()

def create_segwit_txid(tx_json):
    txid = ""
    tx_data = json.loads(tx_json)
    txid += struct.pack("<I", tx_data["version"])
    txid += compact_size(len(tx_data['vin'])).hex()
    vin = tx_data["vin"][0]
    txid += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
    txid += struct.pack("<I",vin["vout"]).hex()
    txid += "00" # scriptsig size
    txid += struct.pack("<I", vin["sequence"]).hex()
    txid += compact_size(len(vin["scriptsig"])//2).hex()
    for vout in tx_data["vout"]:
        txid += struct.pack("<Q", vout["value"]).hex()
        txid += compact_size(len(vout["scriptpubkey"])//2).hex()
        txid += vout["scriptpubkey"]
    txid += struct.pack("<I", int(tx_data["locktime"])).hex()
    txid_hash = hash256(bytes.fromhex(txid))
    return txid_hash[::-1].hex()

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

def create_witness_root_hash(folder):
    wtxid = ["0000000000000000000000000000000000000000000000000000000000000000"]
    for file in os.listdir(folder):
        f = open(f"{folder}/{file}")
        data = json.load(f)
        if data["vin"][0]["prevout"]["scriptpubkey_type"] == "v0_p2wpkh":
            wtxid.append(wtxid_segwit(json.dumps(data)))
        elif data["vin"][0]["prevout"]["scriptpubkey_type"] == "p2pkh":
            wtxid.append(create_tx_id(json.dumps(data)))
    return bytes.fromhex(merkle(wtxid))
        
def calculate_coinbase(folder):
    # txidlist = ["0000000000000000000000000000000000000000000000000000000000000000"] + txidlist
    witness_root_hash = create_witness_root_hash(folder)
    witness_root_hash = witness_root_hash[::-1].hex()
    coinbase = ""
    version = "01000000"
    marker = "00"
    flag = "01"
    input_count = "01"
    txid = (b'\x00'*32).hex()
    vout = "ffffffff"
    scriptsigsize = "1d"
    scirptsig = "03000000184d696e656420627920416e74506f6f6c373946205b8160a4"
    sequence = "ffffffff"
    outputcount = "02"
    coinbase = version + marker + flag + input_count + txid + vout + scriptsigsize + scirptsig + sequence + outputcount
    
    txid_hash = witness_root_hash + "0000000000000000000000000000000000000000000000000000000000000000"
    witness_commitment = hash256(bytes.fromhex(txid_hash)).hex()
    coinbase += "f595814a00000000" + "19" + "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac" # vout 1
    coinbase += "0000000000000000" + "26" + f"6a24aa21a9ed{witness_commitment}" # vout 2
    # 6a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db
    # add witness
    coinbase += "01" + "20" + "0000000000000000000000000000000000000000000000000000000000000000"
    coinbase += "00000000" # add locktime
    return coinbase

# def calculate_coinbase_p2wpkh(wtxidlist):
#     wtxidlist = ["0000000000000000000000000000000000000000000000000000000000000000"] + wtxidlist
#     witness_root_hash = bytes.fromhex(merkle(wtxidlist))
#     witness_root_hash = witness_root_hash[::-1].hex()
#     coinbase = ""
#     version = "01000000"
#     marker = "00"
#     flag = "01"
#     input_count = "01"
#     txid = (b'\x00'*32).hex()
#     vout = "ffffffff"
#     scriptsigsize = "1d"
#     scirptsig = "03000000184d696e656420627920416e74506f6f6c373946205b8160a4"
#     sequence = "ffffffff"
#     outputcount = "02"
#     coinbase = version + marker + flag + input_count + txid + vout + scriptsigsize + scirptsig + sequence + outputcount
    
#     txid_hash = witness_root_hash + "0000000000000000000000000000000000000000000000000000000000000000"
#     witness_commitment = hash256(bytes.fromhex(txid_hash)).hex()
#     coinbase += "f595814a00000000" + "19" + "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac" # vout 1
#     coinbase += "0000000000000000" + "26" + f"6a24aa21a9ed{witness_commitment}" # vout 2
#     # 6a24aa21a9edfaa194df59043645ba0f58aad74bfd5693fa497093174d12a4bb3b0574a878db
#     # add witness
#     coinbase += "01" + "20" + "0000000000000000000000000000000000000000000000000000000000000000"
#     coinbase += "00000000" # add locktime
#     return coinbase

def txid_list_segwit(folder):
    txidlist = []
    for file in os.listdir(folder):
        f = open(folder+"/"+file)
        tx_data = json.load(f)
        txidlist.append(create_segwit_txid(json.dumps(tx_data)))
    return txidlist

def wtxid_segwit(tx_json):
    wtxid = ""
    tx_data = json.loads(tx_json)
    wtxid += struct.pack("<I", tx_data["version"]).hex()
    wtxid += "00" # marker
    wtxid += "01" # flag
    wtxid += "01" # input count
    
    vin = tx_data["vin"][0]
    wtxid += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
    wtxid += struct.pack("<I", vin["vout"]).hex()
    wtxid += "00" # scriptsig size
    wtxid += struct.pack("<I", vin["sequence"]).hex()
    
    wtxid += compact_size(len(vin["vout"])//2).hex()
    for vout in tx_data["vout"]:
        wtxid += struct.pack("<Q", vout["value"]).hex()
        wtxid += compact_size(len(vout["scriptpubkey"])//2).hex()
        wtxid += vout["scriptpubkey"]
    
    witness = vin["witness"]
    wtxid += "02" # stack size
    wtxid += compact_size(len(witness[0])//2).hex()
    wtxid += witness[0]
    wtxid += compact_size(len(witness[1])//2).hex()
    wtxid += witness[1]
    wtxid += struct.pack("<I", int(tx_data["locktime"])).hex()
    wtxid_hash = hash256(bytes.fromhex(wtxid))
    return wtxid_hash[::-1].hex()
    
def txid_list():
    txid_list = []
    for file in os.listdir("./verified"):
        f = open("./verified/"+file)
        tx_data = json.load(f)
        txid_list.append(create_tx_id(json.dumps(tx_data)))
    return txid_list
    
def blockheader(txidlst):
    ver = "00000020"
    prevblock = "0000000000000000000000000000000000000000000000000000000000000000"
    txidlst = ["0000000000000000000000000000000000000000000000000000000000000000"] + txidlst
    merkle_root = merkle(txidlst)
    target_bits = 0x1f00ffff
    exp = target_bits >> 24
    mant = target_bits & 0xffffff
    target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
    target_str = bytes.fromhex(target_hexstr)
    nonce = 0

    while nonce < 0x100000000:
        header = bytes.fromhex(ver) + bytes.fromhex(prevblock)[::-1] +\
            bytes.fromhex(merkle_root)[::-1] + struct.pack("<LLL", int(hex(int(time.time())),16), target_bits, nonce)
        hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        # print(nonce, (hash[::-1]).hex())
        if hash[::-1] < target_str:
            return header.hex()
        nonce += 1
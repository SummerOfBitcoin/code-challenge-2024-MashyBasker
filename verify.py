import os
import json
from shutil import copyfile
import hashlib
import ecdsa
import hashlib
import struct

### Read and Serialize JSON files ###
MEM_DIR = "./mempool/"
transaction_files = os.listdir(MEM_DIR)

def filter_with_script_type(transaction_files):
    for file in transaction_files:
        f = open(MEM_DIR+file)
        tx_data = json.load(f)
        script_name = tx_data['vin'][0]['prevout']['scriptpubkey_type']
        os.makedirs(script_name, exist_ok=True)
        #print(f"./{script_name}/{file}")
        print(f"[INFO] copying {MEM_DIR+file} to {script_name}")
        copyfile(MEM_DIR+file, f"{script_name}/{file}")
        
print("Filtering files based on script type")

### Validation scripts ###
def p2pkh_script(final_asm, data, idx):
    opcodes = final_asm.split(" ")
    stack = []
    i = 0
    equal_verify = True
    while i < len(opcodes):
        if opcodes[i].startswith("OP_PUSHBYTES"):
            stack.append(opcodes[i+1])
        elif opcodes[i] == "OP_DUP":
            pubkey = stack.pop()
            stack.append(pubkey)
            stack.append(pubkey)
        elif opcodes[i] == "OP_HASH160":
            pubkey = stack.pop()
            sha256_val = hashlib.sha256(bytes.fromhex(pubkey)).digest()
            ripemd_hash = hashlib.new('ripemd160', sha256_val).digest()
            stack.append(ripemd_hash.hex())
        elif opcodes[i] == "OP_EQUALVERIFY":
            last_elem1 = stack.pop()
            last_elem2 = stack.pop()
            if last_elem1 != last_elem2:
                print("False in OP_EQUALVERIFY")
                return False
        elif opcodes[i] == "OP_CHECKSIG":
            tx_hash = transaction_hash_with_id(data, idx).hex()
            # print(tx_hash)
            val = verify_signature(stack, tx_hash)
            if val == False:
                return False
            else :
                return True
        i += 1
        # print(stack)
            
    return equal_verify

def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def compact_size(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')
    
def transaction_hash_with_id(tx_json, idx):
    tx_data = json.loads(tx_json)
    message = ""
    message += struct.pack('<I', tx_data['version']).hex()
    # message += struct.pack('<B', len(tx_data['vin'])).hex()
    message += compact_size(len(tx_data['vin'])).hex()
    for i, vin in enumerate(tx_data['vin']):
        if i == idx:
            message += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
            message += struct.pack('<I', vin['vout']).hex()
            # message += hex(len(vin['prevout']['scriptpubkey'])//2)[2:]
            message += compact_size(len(vin['prevout']['scriptpubkey'])//2).hex()
            message += vin['prevout']['scriptpubkey']
            message += struct.pack('<I', vin['sequence']).hex()
        else:
            message += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
            message += struct.pack('<I', vin['vout']).hex()
            message += "00"
            message += ""
            message += struct.pack('<I', vin['sequence']).hex()
    message += compact_size(len(tx_data['vout'])).hex()
    for vout in tx_data['vout']:
        # message += struct.pack('<Q', vout['value']).hex()[2:]
        message += struct.pack('<Q', int(vout['value'])).hex()
        # message += hex(len(vout['scriptpubkey'])//2)[2:]
        message += compact_size(len(vout['scriptpubkey'])//2).hex()
        message += vout['scriptpubkey']
    message += struct.pack('<I', tx_data['locktime']).hex()
    # add SIGHASH
    message += "01000000"
    print(message)
    return hash256(bytes.fromhex(message))

    
# def transaction_hash(transaction_json):
#     transaction_data = json.loads(transaction_json)
#     message = ""
#     message += struct.pack('<I', transaction_data['version']).hex()
#     message += struct.pack('<B', len(transaction_data['vin'])).hex()
#     # print(struct.pack('<B', len(transaction_data['vin'])).hex())
#     for vin in transaction_data['vin']:
#         message += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
#         message += struct.pack('<I', vin['vout']).hex()
#         message += hex(len(vin['prevout']['scriptpubkey'])//2)[2:]
#         message += vin['prevout']['scriptpubkey']
#         message += struct.pack('<I', vin['sequence']).hex()
        
#     message += struct.pack('<B', len(transaction_data['vout'])).hex()
#     for vout in transaction_data['vout']:
#         # message += struct.pack('<Q', vout['value']).hex()[2:]
#         message += struct.pack('<Q', int(vout['value'])).hex()
#         message += hex(len(vout['scriptpubkey'])//2)[2:]
#         message += vout['scriptpubkey']
#     message += struct.pack('<I', transaction_data['locktime']).hex()
#     # add SIGHASH
#     message += "01000000"
#     if len(message)%2 == 0:
#         pass
#     else:
#         message += "0"
#     # print(message)
#     return hash256(bytes.fromhex(message))
        

def verify_signature(stack, transaction_hash):
    # Convert public key to bytes
    if len(stack) < 2:
        return False
    pubkey = stack.pop()
    signature = stack.pop()[:-2]
    try:
        # Create an ECDSA verifier
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=ecdsa.SECP256k1)

        # Verify the signature
        is_valid = vk.verify_digest(bytes.fromhex(signature), bytes.fromhex(transaction_hash), sigdecode=ecdsa.util.sigdecode_der)
        if is_valid:
            # print("Signature is valid")
            result = True
        else:
            # print("Signature is invalid")
            result = False

    except Exception as e:
        # print("Error occurred during verification:", e)
        result = False

    return result
    
def p2pkh_validate(data):
    vin_list = data['vin']
    ans = False
    for i, vin in enumerate(vin_list):
        pubkey_asm = vin['prevout']['scriptpubkey_asm']
        scriptsig_asm = vin['scriptsig_asm']
        final_asm = scriptsig_asm + " " + pubkey_asm
        ans = p2pkh_script(final_asm, json.dumps(data), i)
    return ans

# p2pkh_files = os.listdir("./p2pkh/")
p2pkh_files = os.listdir("./testdata/")
c = 0
for file in p2pkh_files:
    # f = open('./p2pkh/'+file)
    f = open('./testdata/'+file)
    if p2pkh_validate(json.load(f)) == True:
        # print("The script is valid")
        c += 1
        print(file)
    else:
        # print("The script is invalid")
        pass

# print(f"{c} has false in OP_EQUAVERIFY")
print(c)

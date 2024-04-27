import os
import json
from shutil import copyfile, copytree, copy2
from Crypto.Hash import RIPEMD160
import hashlib
import ecdsa
import hashlib
import struct

def filter_p2pkh(input_folder, output_folder):
    # Ensure the output folder exists or create it
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Iterate through each JSON file in the input folder
    for filename in os.listdir(input_folder):
        if filename.endswith(".json"):
            input_file_path = os.path.join(input_folder, filename)
            output_file_path = os.path.join(output_folder, filename)

            with open(input_file_path, "r") as input_file:
                data = json.load(input_file)

                # Check if all inputs have "scriptpubkey_type": "p2pkh"
                all_p2pkh = all(vin["prevout"]["scriptpubkey_type"] == "p2pkh" for vin in data["vin"])

                if all_p2pkh:
                    # Write the transaction to the output folder
                    copyfile(input_file_path, output_file_path)

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
            ripemd_hash = RIPEMD160.new(sha256_val).digest()
            stack.append(ripemd_hash.hex())
        elif opcodes[i] == "OP_EQUALVERIFY":
            last_elem1 = stack.pop()
            last_elem2 = stack.pop()
            if last_elem1 != last_elem2:
                print("False in OP_EQUALVERIFY")
                return False
        elif opcodes[i] == "OP_CHECKSIG":
            tx_hash = transaction_hash_with_id(data, idx).hex()
            # tx_hash = create_segwit_tx_hash(data, idx).hex()
            val = verify_signature(stack, tx_hash)
            if val == False:
                return False
            else :
                return True
        # print(stack)
        i += 1
            
    return equal_verify

def p2wpkh_script(final_asm, data, idx):
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
            ripemd_hash = RIPEMD160.new(sha256_val).digest()
            stack.append(ripemd_hash.hex())
        elif opcodes[i] == "OP_EQUALVERIFY":
            last_elem1 = stack.pop()
            last_elem2 = stack.pop()
            if last_elem1 != last_elem2:
                print("False in OP_EQUALVERIFY")
                return False
        elif opcodes[i] == "OP_CHECKSIG":
            # tx_hash = transaction_hash_with_id(data, idx).hex()
            tx_hash = create_segwit_tx_hash(data, idx).hex()
            val = verify_signature(stack, tx_hash)
            if val == False:
                return False
            else :
                return True
        # print(stack)
        i += 1
            
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
    message += compact_size(len(tx_data['vin'])).hex()
    for i, vin in enumerate(tx_data['vin']):
        if i == idx:
            message += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
            message += struct.pack('<I', int(vin['vout'])).hex()
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
        message += struct.pack('<Q', int(vout['value'])).hex()
        message += compact_size(len(vout['scriptpubkey'])//2).hex()
        message += vout['scriptpubkey']
    message += struct.pack('<I', tx_data['locktime']).hex()
    message += "01000000" # sighash
    # print(message)
    return hash256(bytes.fromhex(message))
    
def verify_signature(stack, transaction_hash):
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


def verify_transaction_p2pkh(src_folder, dest_folder):
    files = os.listdir(src_folder)
    os.makedirs(dest_folder, exist_ok=True)
    for file in files:
        f = open(src_folder+"/"+file)
        if p2pkh_validate(json.load(f)) == True:
            copyfile(f"{src_folder}/{file}", f"{dest_folder}/{file}")
        else:
            pass

def verify_transaction_p2wpkh(src_folder, dest_folder):
    files = os.listdir(src_folder)
    os.makedirs(dest_folder, exist_ok=True)
    for file in files:
        f = open(src_folder+"/"+file)
        data = json.load(f)
        if p2wpkh_validate(data) == True:
            json_str = json.dumps(data)
            if len(json_str.encode("utf-8")) != 94429:
                copyfile(f"{src_folder}/{file}", f"{dest_folder}/{file}")
            else:
                pass
            

def filter_p2wpkh(input_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)

    for filename in os.listdir(input_folder):
        if filename.endswith(".json"):
            input_file_path = os.path.join(input_folder, filename)
            
            # Open and load JSON data
            with open(input_file_path, "r") as f:
                data = json.load(f)
                
                if len(data.get("vin", [])) == 1 and data.get("vin")[0].get("prevout", {}).get("scriptpubkey_type") == "v0_p2wpkh":
                    copyfile(input_file_path, os.path.join(output_folder, filename))


def merge_folders(source_folder1, source_folder2, destination_folder):
    # Create the destination folder if it doesn't exist
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    # Iterate through the contents of source_folder1
    for item in os.listdir(source_folder1):
        source_item = os.path.join(source_folder1, item)
        destination_item = os.path.join(destination_folder, item)
        
        # Copy each item from source_folder1 to the destination folder
        if os.path.isdir(source_item):
            copytree(source_item, destination_item)
        else:
            copy2(source_item, destination_item)

    # Iterate through the contents of source_folder2
    for item in os.listdir(source_folder2):
        source_item = os.path.join(source_folder2, item)
        destination_item = os.path.join(destination_folder, item)
        
        # Copy each item from source_folder2 to the destination folder
        if os.path.isdir(source_item):
            copytree(source_item, destination_item)
        else:
            copy2(source_item, destination_item)

def create_asm(signature, pubkey, scriptpubkey_hash):
    script = f"OP_PUSHBYTES_72 {signature} OP_PUSHBYTES_33 {pubkey} OP_DUP OP_HASH160 OP_PUSHBYTES_20 {scriptpubkey_hash} OP_EQUALVERIFY OP_CHECKSIG"
    return script
       
def p2wpkh_validate(data):
    vin_list = data['vin']
    ans = False
    for i, vin in enumerate(vin_list):
        signature = vin["witness"][0]
        pubkey = vin["witness"][1]
        scriptpubkey_hash = vin["prevout"]["scriptpubkey_asm"].split(" ")[-1]
        asm_script = create_asm(signature, pubkey, scriptpubkey_hash)
        ans = p2wpkh_script(asm_script, json.dumps(data), i)
    return ans

def create_segwit_tx_hash(tx_json, idx):
    tx_data = json.loads(tx_json)
    msg = ""
    msg += struct.pack('<I', tx_data['version']).hex()
    
    vin = tx_data['vin'][0]
    txid = ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
    vout = struct.pack('<I', vin['vout']).hex()
    inputs = txid + vout
    input_hash = hash256(bytes.fromhex(inputs)).hex()
    msg += input_hash
    
    sequence = struct.pack('<I', vin['sequence']).hex()
    msg += hash256(bytes.fromhex(sequence)).hex()
    msg += inputs
    pubkeyhash = tx_data['vin'][0]['prevout']['scriptpubkey_asm'].split(" ")[-1]
    scriptcode = f"1976a914{pubkeyhash}88ac"
    msg += scriptcode
    amount = struct.pack('<Q', int(tx_data['vin'][0]['prevout']['value'])).hex()
    msg += amount
    msg += sequence
    
    outputs = ""
    for vout in tx_data['vout']:
        outputs += struct.pack('<Q', int(vout['value'])).hex()
        outputs += compact_size(len(vout['scriptpubkey'])//2).hex()
        outputs += vout['scriptpubkey']
    outputs_hash = hash256(bytes.fromhex(outputs)).hex()
    msg += outputs_hash
    msg += struct.pack('<I', tx_data['locktime']).hex()
    msg += "01000000"
    return hash256(bytes.fromhex(msg))
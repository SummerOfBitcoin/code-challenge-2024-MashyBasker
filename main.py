from mining import calculate_coinbase, txid_list, blockheader
from verify import filter_p2pkh, filter_p2wpkh, verify_transaction_p2pkh, verify_transaction_p2wpkh, merge_folders

def write_to_file(txidlist, coinbase, block_header):
    with open("output.txt", "a") as f:
        f.write(block_header)
        f.write(f"\n{coinbase}")
        empty_txid = (b'\x00'*32).hex()
        f.write(f"\n{empty_txid}")
        for txid in txidlist:
            f.write(f"\n{txid}")

filter_p2pkh("./mempool", "./p2pkh")
filter_p2wpkh("./mempool", "./v0_p2wpkh")

verify_transaction_p2pkh("./p2pkh", "./p2pkh_verified")
verify_transaction_p2wpkh("./v0_p2wpkh", "./v0_p2wpkh_verified")
merge_folders("./p2pkh_verified", "./v0_p2wpkh_verified", "./verified")
txidlist = txid_list()
coinbase = calculate_coinbase("./verified")
block_header = blockheader(txidlist)
write_to_file(txidlist, coinbase, block_header)
        


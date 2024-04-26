from mining import calculate_coinbase, txid_list, blockheader
from verify import filter_transactions, verify_transaction

# txidlist = txid_list()
# coinbase = calculate_coinbase()
# block_header = blockheader(txidlist)

def write_to_file(txidlist, coinbase, block_header):
    with open("output.txt", "a") as f:
        f.write(block_header)
        f.write(f"\n{coinbase}")
        empty_txid = (b'\x00'*32).hex()
        f.write(f"\n{empty_txid}")
        for txid in txidlist:
            f.write(f"\n{txid}")

filter_transactions("./mempool", "./p2pkh")
verify_transaction("./p2pkh")
txidlist = txid_list()
coinbase = calculate_coinbase()
block_header = blockheader(txidlist)
write_to_file(txidlist, coinbase, block_header)
        


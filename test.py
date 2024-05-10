from attack.ecdsa_hnp import ECDSA, ECDSASolver, make_klen_list

# This script will also generate two files, signatures.txt and pubkey.txt to be used as input for the main.py script

if __name__ == "__main__":
    m = 60
    k = 512
    ecdsa = ECDSA(nbits=521)
    lines = lines, k_list, d = ecdsa.sample(m,make_klen_list(k,m))
    solver = ECDSASolver(ecdsa,lines,m=m)
    recover_pk,res = solver("bkz-enum")
    if not res.success:
        print("Failed to recover private key")
    assert d == recover_pk
    print("Private key recovered successfully!")
# CVE-2024-31497 POC

This vulnerability exploits the biased ECDSA nonce generation in the ```ecc-ssh.c``` file. The nonce is generated with $sha512(ID\ ||\ sha512(privKey)\ ||\ sha1(data))\ mod\ q$ leaving the top 9 bits to zero. In order to recover the private key we need 60 signatures but with 58 we still have 50% probability of success.

 Vuln discovered by Bäumer and Marcus Brinkmann.  


## Requirements

In order to use this exploit you must have [sagemath](https://github.com/sagemath/sage/) and the python dependencies in ```requirements.txt``` installed. 


## Attack Surface

1. Extract the ECDSA signatures from 60 verified GitHub commits that used PuTTy or TortoiseGit to sign the commit content. 

2. Another possible attack is to set up a rogue SSH server where victims connect (using PuTTY or Pageant) and after several connections you can retrieve the 60 signatures to recover the private key. 

## Arguments

- The signature file must contain the **message hash**, a space and the values of **r** and **s** concatenated.

- The **pubkey** file input, can be in raw, PEM, DER or OpenSSH format.

## Acknowledgements

This poc uses part of the [malb](https://github.com/malb) implementation of the paper [On Bounded Distance Decoding with Predicate: Breaking the "Lattice Barrier" for the Hidden Number Problem](https://eprint.iacr.org/2020/1540.pdf)

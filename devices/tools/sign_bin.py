#!/usr/bin/env python3

import os
import sys

from Crypto.Hash import SHA384
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

# Key pair generation
# openssl ecparam -name secp384r1 -genkey -noout -outform der -out private.der
# openssl ec -in private.der -inform der -pubout -out public.der -outform der

def sign(msg, private_key_file):
    sha384_hash = SHA384.new(msg)
    private_key = ECC.import_key(open(private_key_file, 'rb').read())
    signer = DSS.new(private_key, 'fips-186-3', encoding = 'der')
    return signer.sign(sha384_hash)

def check_signature(msg, signature, public_key):
    sha384_hash = SHA384.new(msg)
    verifier = DSS.new(public_key, 'fips-186-3', encoding = 'der')
    try:
        verifier.verify(sha384_hash, signature)
        return True
    except ValueError:
        return False

def main():
    try:
        file_name = sys.argv[1]
    except:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)

    public_key = ECC.import_key(
                                bytes(
                                      [
                                       0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
                                       0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
                                       0x03, 0x62, 0x00, 0x04, 0xd4, 0x23, 0x58, 0x4e, 0x23, 0xd8,
                                       0x64, 0x81, 0x20, 0xc1, 0xf7, 0x7b, 0xd0, 0x47, 0x7a, 0xec,
                                       0xc0, 0x68, 0x86, 0x1d, 0xf2, 0x8d, 0x1d, 0x96, 0x98, 0x10,
                                       0x93, 0xd3, 0x73, 0x00, 0x13, 0xc2, 0x3d, 0x5e, 0xc7, 0x66,
                                       0xfe, 0x1b, 0x09, 0xce, 0x4a, 0xc6, 0x7f, 0x25, 0x25, 0xf0,
                                       0x06, 0x96, 0x38, 0xf6, 0xf0, 0xf2, 0xef, 0xf3, 0x26, 0x69,
                                       0x25, 0x8c, 0x90, 0x56, 0xce, 0xd4, 0x5c, 0x09, 0x56, 0x73,
                                       0xbc, 0x90, 0xf2, 0x81, 0x27, 0xcf, 0x14, 0xe5, 0xbe, 0xcf,
                                       0x09, 0xce, 0xed, 0x3d, 0xca, 0xad, 0xd3, 0x6f, 0xd7, 0x58,
                                       0xc7, 0x12, 0xa0, 0x3d, 0x68, 0x22, 0xb8, 0x0c, 0x10, 0x1b
                                      ]
                                     )
                               )

    with open(file_name, 'rb') as f:
        file_data = f.read()

    print(f'Sign {os.path.basename(file_name)}')

    signature = b''
    while len(signature) < 104:
        signature = sign(file_data, os.path.split(os.path.abspath(sys.argv[0]))[0] + '/priv_key.der')

    with open(f'{file_name}.sec', 'wb') as f:
        f.write(signature)

    print('Verify signature: ', end='')
    with open(f'{file_name}.sec', 'rb') as f:
        print('ok' if (check_signature(file_data, f.read(), public_key)) else 'failed')

if __name__ == '__main__':
    main()

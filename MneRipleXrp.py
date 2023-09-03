import os
import binascii
import requests
import json
from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1

def private_key_to_public_key(private_key):
    private_key_bytes = binascii.unhexlify(private_key)
    private_key_object = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key_object = private_key_object.get_verifying_key()
    public_key_bytes = public_key_object.to_string()
    public_key_hex = binascii.hexlify(public_key_bytes)
    return public_key_hex.decode('utf-8')

def public_key_to_address(public_key):
    public_key_bytes = binascii.unhexlify(public_key)
    sha3_hash = keccak.new(digest_bits=256)
    sha3_hash.update(public_key_bytes)
    hashed_key = sha3_hash.hexdigest()
    address = 'r' + hashed_key[-40:]
    return address

def generate_xrp_address():
    private_key = binascii.hexlify(os.urandom(32)).decode('utf-8')
    public_key = private_key_to_public_key(private_key)
    address = public_key_to_address(public_key)
    return (address, private_key)

def get_xrp_balance(address):
    api_url = f'https://data.ripple.com/v2/accounts/{address}/balances'
    response = requests.get(api_url)
    data = json.loads(response.text)
    if 'balances' in data:
        for balance in data['balances']:
            if balance['currency'].upper() == 'XRP':
                return float(balance['value'])
    return 0.0

def save_to_file(address, private_key, balance):
    with open('found.txt', 'a') as f:
        f.write(f'Ripple Address: {address}\n')
        f.write(f'Private Key: {private_key}\n')
        f.write(f'Balance: {balance} XRP\n\n')

if __name__ == '__main__':
    try:
        while True:
            address, private_key = generate_xrp_address()
            balance = get_xrp_balance(address)
            print('Ripple Address:', address)
            print('Private Key:', private_key)
            print('Balance:', balance, 'XRP')
            if balance > 0:
                save_to_file(address, private_key, balance)
                print('Address with balance saved to found.txt')
    except KeyboardInterrupt:
        print('\nStopped by user.')

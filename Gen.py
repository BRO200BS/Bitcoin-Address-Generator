import time
import os
from Crypto.Hash import SHA256, RIPEMD160
import base58
import ecdsa
from bech32 import bech32_encode, convertbits

def generate_bitcoin_address():
    # Generate private key
    private_key = os.urandom(32)
    fullkey = '80' + private_key.hex()
    sha256a = SHA256.new(bytes.fromhex(fullkey)).hexdigest()
    sha256b = SHA256.new(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8]))

    # Get public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    # Get compressed public key
    compressed_public_key = '02' if y % 2 == 0 else '03'
    compressed_public_key += x.to_bytes(32, 'big').hex()

    # Get P2PKH address
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    # Get compressed P2PKH address
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    # Get P2SH address
    redeem_script = '21' + compressed_public_key + 'ac'
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(redeem_script)).digest())
    script_hash = '05' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(script_hash)).digest()).hexdigest()[:8]
    p2sh_address = base58.b58encode(bytes.fromhex(script_hash + checksum))

    # Get Bech32 address
    witness_program = bytes([0x00, 0x14]) + hash160.digest()
    bech32_address = bech32_encode('bc', convertbits(witness_program, 8, 5))

    return {
        'private_key': private_key.hex(),
        'WIF': WIF.decode(),
        'public_key': public_key,
        'compressed_public_key': compressed_public_key,
        'p2pkh_address': p2pkh_address.decode(),
        'compressed_p2pkh_address': compressed_p2pkh_address.decode(),
        'p2sh_address': p2sh_address.decode(),
        'bech32_address': bech32_address
    }

num_addresses = int(input('Enter the number of addresses to generate: '))
for i in range(num_addresses):
    address_info = generate_bitcoin_address()
    print(f"Address #{i+1}:")
    print(f"Private Key: {address_info['private_key']}")
    print(f"WIF: {address_info['WIF']}")
    print(f"Public Key: {address_info['public_key']}")
    print(f"Compressed Public Key: {address_info['compressed_public_key']}")
    print(f"P2PKH Address: {address_info['p2pkh_address']}")
    print(f"Compressed P2PKH Address: {address_info['compressed_p2pkh_address']}")
    print(f"P2SH Address: {address_info['p2sh_address']}")
    print(f"Bech32 Address: {address_info['bech32_address']}\n")

    print("Remember to save your address")

time.sleep(100000)

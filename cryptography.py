import argparse
import json
import os
import sys
from Crypto.Cipher import AES

def pad(data):
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def read_public_key(filename): # Read the public key from file
    with open(filename, "r") as f:
        lines = f.read().splitlines()
        n = int(lines[0])
        e = int(lines[1])
        return (n, e)

def read_private_key(filename): # Read the private key from file
    with open(filename, "r") as f:
        lines = f.read().splitlines()
        n = int(lines[0])
        d = int(lines[1])
        return (n, d)

def encrypt_file(pubkey_file, input_file, output_file):
    # Read RSA public key.
    n, e = read_public_key(pubkey_file)
    # Read plaintext.
    with open(input_file, "rb") as f:
        plaintext = f.read()
    # Generate a random AES-128 key (16 bytes).
    aes_key = os.urandom(16)
    padded_plaintext = pad(plaintext)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plaintext)
    aes_key_int = int.from_bytes(aes_key, byteorder="big")  # RSA encrypt the AES key.
    encrypted_key = pow(aes_key_int, e, n)

    # Store the RSA-encrypted AES key and AES ciphertext in JSON.
    output_data = {
        "encrypted_key": hex(encrypted_key)[2:],
        "ciphertext": ciphertext.hex()
    }
    with open(output_file, "w") as f:
        json.dump(output_data, f)
    print("Encryption successful. Output written to", output_file)

def decrypt_file(privkey_file, input_file, output_file):
    # Read RSA private key.
    n, d = read_private_key(privkey_file)
    # Read the JSON file containing the RSA-encrypted key and ciphertext.
    with open(input_file, "r") as f:
        data = json.load(f)
    encrypted_key_hex = data["encrypted_key"]
    ciphertext_hex = data["ciphertext"]
    encrypted_key = int(encrypted_key_hex, 16)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # RSA decrypt to recover the AES key.
    aes_key_int = pow(encrypted_key, d, n)
    aes_key = aes_key_int.to_bytes(16, byteorder="big")
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext)

    # Write plaintext to output file.
    with open(output_file, "wb") as f:
        f.write(plaintext)
    print("Decryption successful. Output written to", output_file)

def main():
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt files using AES and RSA")
    parser.add_argument("mode", choices=["-e", "-d"], help="-e to encrypt, -d to decrypt")
    parser.add_argument("keyfile", help="Key file (public for encryption, private for decryption)")
    parser.add_argument("infile", help="Input file to process")
    parser.add_argument("outfile", help="Output file")
    args = parser.parse_args()
    
    if args.mode == "-e":
        encrypt_file(args.keyfile, args.infile, args.outfile)
    else:
        decrypt_file(args.keyfile, args.infile, args.outfile)

if __name__ == "__main__":
    main()

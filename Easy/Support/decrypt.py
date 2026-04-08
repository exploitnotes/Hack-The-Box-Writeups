#!/usr/bin/env python3
"""
XOR Decryption Script for .NET embedded credentials
Decrypts base64-encoded XOR+0xDF encrypted strings
"""

import base64
import sys

def decrypt_xor(enc_password, key, xor_constant=0xDF):
    """
    Decrypt XOR-encrypted base64 string
    
    Args:
        enc_password (str): Base64-encoded encrypted password
        key (str or bytes): XOR key
        xor_constant (int): Additional XOR constant (default 0xDF)
    
    Returns:
        str: Decrypted password
    """
    # Convert key to bytes if it's a string
    if isinstance(key, str):
        key = key.encode()
    
    # Decode base64
    data = base64.b64decode(enc_password)
    
    # XOR decrypt
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append((data[i] ^ key[i % len(key)]) ^ xor_constant)
    
    return decoded.decode()


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 decrypt_xor.py <encrypted_password> <key> [xor_constant]")
        print("\nExample:")
        print("  python3 decrypt_xor.py 'QmFzZTY0RW5jb2RlZFBhc3N3b3JkMTIzIQ==' 'support'")
        print("  python3 decrypt_xor.py 'QmFzZTY0RW5jb2RlZFBhc3N3b3JkMTIzIQ==' 'support' 223")
        sys.exit(1)
    
    enc_password = sys.argv[1]
    key = sys.argv[2]
    xor_constant = int(sys.argv[3]) if len(sys.argv) > 3 else 0xDF
    
    try:
        decrypted = decrypt_xor(enc_password, key, xor_constant)
        print(f"[+] Decrypted: {decrypted}")
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import sys
from cryptography.fernet import Fernet

if len(sys.argv) != 3:
    print("Usage: decrypt_password.py <encrypted> <key_file>", file=sys.stderr)
    sys.exit(1)

encrypted = sys.argv[1]
with open(sys.argv[2], 'rb') as f:
    key = f.read()

cipher = Fernet(key)
print(cipher.decrypt(encrypted.encode()).decode())
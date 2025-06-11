from cryptography.fernet import Fernet

key = open("/etc/ansible/suma_key", "rb").read()
cipher = Fernet(key)

encrypted_password = cipher.encrypt(b"test").decode()
print(encrypted_password)

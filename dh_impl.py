import random
import hashlib
from Crypto.Cipher import AES
import base64

# Parameters from the assignment
g = 5
p = 37

def generate_key():
    return random.randint(1, p-1)

def compute_public_key(private_key, g, p):
    return (g ** private_key) % p

def compute_shared_secret(private_key, public_key, p):
    return (public_key ** private_key) % p

def get_key_hash(shared_secret):
    m = hashlib.sha256()
    m.update(str(shared_secret).encode())
    # Return the first 128 bits of the key
    return m.digest()[:16]

def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length] * length)

def unpad(data):
    return data[:-data[-1]]

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode())
    encrypted_text = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_text).decode()

def decrypt(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded_encrypted_message = base64.b64decode(encrypted_message)
    decrypted_text = unpad(cipher.decrypt(decoded_encrypted_message)).decode()
    return decrypted_text


# Diffie-Hellman key exchange
alice_private_key = generate_key()
bob_private_key = generate_key()

alice_public_key = compute_public_key(alice_private_key, g, p)
bob_public_key = compute_public_key(bob_private_key, g, p)

alice_shared_secret = compute_shared_secret(alice_private_key, bob_public_key, p)
bob_shared_secret = compute_shared_secret(bob_private_key, alice_public_key, p)

assert alice_shared_secret == bob_shared_secret

key_128 = get_key_hash(alice_shared_secret)

#Encrypting and decrypting a message
message = "Somebody once told me the world is gonna roll me I ain't the smartest tool in the shed"
encrypted_message = encrypt(message, key_128)
decrypted_message = decrypt(encrypted_message, key_128)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")

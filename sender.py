#Establish a shared secret with Diffie-Hellman key exchange
# Alex Espinoza

#import the necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
    # Libraries for TCP socket API
import socket
from cryptography.hazmat.primitives import serialization, hashes
    # RSA library
from cryptography.hazmat.primitives.asymmetric import rsa
    # HKDF library
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Global variables
p = 23
g = 5

shared_secrets_match = False
# Function to generate Diffie-Hellman private key
def generate_private_key(p):
    from random import randint
    # Generate a private key less than p
    return randint(2, p-2)

# Function to generate Diffie-Hellman public key
def generate_public_key(g, private_key, p):
    # public_key = g^private_key mod p
    return pow(g, private_key, p)

# Function to compute shared secret key, requires other party's public key
def compute_shared_secret(other_public_key, private_key, p):
    # shared_secret = other_public_key^private_key mod p
    return pow(other_public_key, private_key, p)

# Generate Diffie-Hellman private key
sender_DH_private_key = generate_private_key(p)
# Generate Diffie-Hellman public key
sender_DH_public_key = generate_public_key(g, sender_DH_private_key, p)
# Public key must be converted to bytes before it can be sent
sender_DH_public_key_bytes = sender_DH_public_key.to_bytes((sender_DH_public_key.bit_length() + 7) // 8, 'big')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 50101))  # Listen on port 50101
server_socket.listen()

print("Server listening...")
conn, addr = server_socket.accept()
with conn:
    print('Connected by', addr)
    receiver_DH_public_key = conn.recv(1024)  # Get receiver.py's public key
    conn.sendall(sender_DH_public_key_bytes)  # Send the sender.py's public key.

    # Reverting the public key from bytes back to an integer
    receiver_DH_public_key = int.from_bytes(receiver_DH_public_key, 'big')

    #Compute the shared secret
    shared_secret = compute_shared_secret(receiver_DH_public_key, sender_DH_private_key, p)
    print("Shared Secret Sender.py:", shared_secret)

    # Send the shared secret to reciever.py
    conn.sendall(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'))

    # Recieve the shared secret from reciever.py and turn it back into an integer
    receiver_shared_secret = int.from_bytes(conn.recv(1024), 'big')

    # Compare shared secrets to make sure they match and update shared_secrets_match
    if shared_secret == receiver_shared_secret:
        shared_secrets_match = True
        print("Shared secrets match")
    else:
        shared_secrets_match = False
        print("Shared secrets do not match")

# Setup HKDF parameters for AES key derivation
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'bytes', # Will convert 'bytes' ASCII characters into a byte value
    info=b'bytes', # Will convert 'bytes' ASCII characters into a byte value
    backend=default_backend()
)

# Generate the AES key, shared secret needs to be converted to bytes before it can be used
shared_secret = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big') # Convert shared secret to bytes
aes_key = hkdf.derive(shared_secret)
shared_secret = int.from_bytes(shared_secret, 'big') # Convert shared secret back to an integer

# Print the AES key
print("AES Key:", aes_key)

# Encrypting the file with the AES key
file_path = 'test.txt'
encrypted_file_path = 'test_encrypted.txt'
iv = b'IVkey'  # Hardcoded IV key
key = aes_key


#Create a function to encrypt the file
def encrypt_file(file_path, encrypted_file_path, key, iv):
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as infile:
        with open(encrypted_file_path, 'wb') as outfile:
            outfile.write(iv)  # It's common to prepend the IV to the encrypted file

            while True:
                chunk = infile.read(1024 * 16)  # Read in chunks of 16 bytes
                if len(chunk) == 0:
                    break  # End of file
                elif len(chunk) % 16 != 0:
                    # Pad the final chunk if necessary
                    chunk += b' ' * (16 - len(chunk) % 16)
                
                outfile.write(encryptor.update(chunk))
            
            outfile.write(encryptor.finalize())

encrypt_file(file_path, encrypted_file_path, aes_key, iv)




# # Generate RSA key pair
# private_key_rsa = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )

# public_key_rsa = private_key_rsa.public_key()

# # Sign the DH public key with RSA
# rsa_private_key = private_key_rsa
# signature = rsa_private_key.sign(
#     public_key_serialized,
#     padding.PSS(
#         mgf=padding.MGF1(hashes.SHA256()),
#         salt_length=padding.PSS.MAX_LENGTH,
#     ),
#     hashes.SHA256(),
# )

# Encrypt the message with 

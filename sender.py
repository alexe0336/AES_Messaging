#Establish a shared secret with Diffie-Hellman key exchange
# Alex Espinoza

#import the necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
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

# Share the public key with receiver.py get the receivers public key
# # Assuming `public_key` is the server's (receiver's) RSA public key
# public_key_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

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
    conn.sendall(sender_DH_public_key)  # Send the sender.py's public key.

#Compute the shared secret
shared_secret = compute_shared_secret(receiver_DH_public_key, sender_DH_private_key, p)
print("Shared Secret:", shared_secret)

# Send the shared secret to reciever.py


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

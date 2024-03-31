#Establish a shared secret with Diffie-Hellman key exchange

#import the necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
    # Libraries for TCP socket API
import socket
from cryptography.hazmat.primitives import serialization

# Global Variables
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

# Generate Diffie-Hellman private key
receiver_DH_private_key = generate_private_key(p)
# Generate Diffie-Hellman public key
receiver_DH_public_key = generate_public_key(g, receiver_DH_private_key, p)

#Share the public key with the sender
# # Assuming `public_key` is the client's (sender's) RSA public key
# public_key_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect(('server_address', 50101))  # Use the server's address
    client_socket.sendall(receiver_DH_public_key)  # Send the receiver.py's public key
    sender_DH_public_key = client_socket.recv(1024)  # Receive sender.py's public key

# Compute shared secret key
shared_secret = compute_shared_secret(sender_DH_public_key, receiver_DH_private_key, p)
print("Shared Secret:", shared_secret)
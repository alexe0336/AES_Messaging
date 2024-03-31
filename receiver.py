#Establish a shared secret with Diffie-Hellman key exchange

#import the necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import time
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

#Public key must be converted to bytes before it can be sent
receiver_DH_public_key_bytes = receiver_DH_public_key.to_bytes((receiver_DH_public_key.bit_length() + 7) // 8, 'big')

senderIP = '10.0.0.92' # Set this to the IP of the computer running the sender.py code
serverPort = 50101 # Set this to the port number the sender.py code is listening on

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    while True:
        try:
            client_socket.connect((senderIP, serverPort))  # Try to connect to the server
            break  # If the connection is successful, break out of the loop
        except ConnectionRefusedError:
            print("Connection failed. Trying again in 5 seconds...")
            time.sleep(5)  # Wait for 5 seconds before trying again

    client_socket.sendall(receiver_DH_public_key_bytes)  # Send the receiver.py's public key
    sender_DH_public_key = client_socket.recv(1024)  # Receive sender.py's public key

# Revert the public key from sender.py that is in bytes back to an integer
sender_DH_public_key = int.from_bytes(sender_DH_public_key, 'big')

# Compute shared secret key
shared_secret = compute_shared_secret(sender_DH_public_key, receiver_DH_private_key, p)
print("Shared Secret:", shared_secret)
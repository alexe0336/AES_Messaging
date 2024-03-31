# Receiver.py, Used to decrypt the encrypted file/message.

#import the necessary libraries
import time
import struct
import socket

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


# Global Variables
p = 23 # Prime number, you can change just make sure you also change it in sender.py
g = 5 # Generator, you can change just make sure you also change it in sender.py

senderIP = '10.0.0.92' # Set this to the IP of the computer running the sender.py code
serverPort = 50101 # Set this to the port number the sender.py code is listening on

# Introduction print statement
print("\nYou are currently running the receiver.py file. This file receives the encrypted file from the sender.py file for decryption.")

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

# Function that sets the receive length of the data incoming
def recv_with_length_prefix(conn):
    # Read the length prefix (32-bit integer, 4 bytes)
    length_prefix = conn.recv(4)
    if not length_prefix:
        raise ConnectionError("\nConnection closed by peer")
    length = struct.unpack('!I', length_prefix)[0]
    
    # Read exactly 'length' bytes
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("\nConnection closed by peer")
        data += chunk
    return data

# Function that sends the data with a length prefix
def send_with_length_prefix(client_socket, data):
    # Prefix each message with its length (32-bit integer, 4 bytes)
    length_prefix = struct.pack('!I', len(data))
    client_socket.sendall(length_prefix + data)


# Generate Diffie-Hellman private key
receiver_DH_private_key = generate_private_key(p)
# Generate Diffie-Hellman public key
receiver_DH_public_key = generate_public_key(g, receiver_DH_private_key, p)

#Public key must be converted to bytes before it can be sent
receiver_DH_public_key_bytes = receiver_DH_public_key.to_bytes((receiver_DH_public_key.bit_length() + 7) // 8, 'big')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    while True:
        try:
            client_socket.connect((senderIP, serverPort))  # Try to connect to the server
            break  # If the connection is successful, break out of the loop
        except ConnectionRefusedError:
            print("\nConnection failed. Trying again in 5 seconds...")
            time.sleep(5)  # Wait for 5 seconds before trying again
    print(f"\nSuccessfully connected to {senderIP} on port {serverPort}")

    # Send receiver.py's DH public key to sender.py, will be sent in bytes
    send_with_length_prefix(client_socket, receiver_DH_public_key_bytes)

    # Receive sender.py's RSA public key
    rsa_public_key_bytes = recv_with_length_prefix(client_socket)

    # Receive sender.py's DH public key
    sender_DH_public_key_bytes = recv_with_length_prefix(client_socket)

    # Receive sender.py's RSA signed DH public key
    sender_signed_DH_public_key = recv_with_length_prefix(client_socket)

    # Convert the RSA public key from bytes back to an RSA public key object
    rsa_public_key = serialization.load_pem_public_key(
    rsa_public_key_bytes,
    backend=default_backend()
)
    # Client verifies the signature
    try:
        # Verify the signature
        rsa_public_key.verify(
            sender_signed_DH_public_key,
            sender_DH_public_key_bytes,  # The original message that was signed
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("\nRSA Signature is valid.")
    except InvalidSignature:
        print("\nRSA Signature is invalid.")

    # Revert the public key from sender.py that is in bytes back to an integer
    sender_DH_public_key = int.from_bytes(sender_DH_public_key_bytes, 'big')

    # Compute shared secret key
    shared_secret = compute_shared_secret(sender_DH_public_key, receiver_DH_private_key, p)

    # Send the shared secret to sender.py
    send_with_length_prefix(client_socket, (shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')))

    # receive the shared secret from receiver.py and turn it back into an integer
    sender_shared_secret = recv_with_length_prefix(client_socket)
    sender_shared_secret = int.from_bytes(sender_shared_secret, 'big')

    # Compare shared secrets to make sure they match and update shared_secrets_match
    if shared_secret == sender_shared_secret:
        print(f"\nShared secrets match: {sender_shared_secret}(sender.py) = {shared_secret}(receiver.py)")
    else:
        print(f"\nShared secrets do not match: {sender_shared_secret}(sender.py) != {shared_secret}(receiver.py)")

# # Close the socket
# client_socket.close()

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

# Reopen socket here
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    while True:
        try:
            client_socket.connect((senderIP, serverPort))  # Try to connect to the server
            break  # If the connection is successful, break out of the loop
        except ConnectionRefusedError:
            print("\nConnection failed to receive encrypted file/message and IV from sender.py. Trying again in 5 seconds...")
            time.sleep(5)  # Wait for 5 seconds before trying again
    print("\nReceiving encrypted file/message and IV from sender.py...")

    # Receive data until there's no more to receive (for the file)
    time.sleep(3) # Wait for 3 seconds to ensure that the sender has sent the file
    
    encrypted_message = recv_with_length_prefix(client_socket)
    print("\nReceived Encrypted File/Message:")

    # Receive the IV
    iv = client_socket.recv(16)
    print(f"\nReceived IV: {iv}")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    print("\nDecrypted Message/File:", decrypted_message.decode())

    # Close the socket
    client_socket.close()
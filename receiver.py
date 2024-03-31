#Establish a shared secret with Diffie-Hellman key exchange

#import the necessary libraries
from cryptography.hazmat.backends import default_backend
import time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

    # Libraries for TCP socket API
import socket

# Global Variables
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
receiver_DH_private_key = generate_private_key(p)
# Generate Diffie-Hellman public key
receiver_DH_public_key = generate_public_key(g, receiver_DH_private_key, p)

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
    print("Connection Succesful")

    client_socket.sendall(receiver_DH_public_key_bytes)  # Send the receiver.py's public key
    sender_signed_DH_public_key = client_socket.recv(1024)  # Receive sender.py's RSA public key
    rsa_public_key_bytes = client_socket.recv(1024)  # Receive sender.py's signed DH public key
    sender_DH_public_key_bytes = client_socket.recv(1024)  # Receive sender.py's DH public key
    print("Received sender.py's public key:", sender_DH_public_key_bytes)

    # Convert the RSA public key from bytes back to an RSA public key object
    # Convert bytes back to an RSA public key object
    rsa_public_key = load_pem_public_key(rsa_public_key_bytes, backend=default_backend())
    print("RSA Public Key:", rsa_public_key)
    # # Client verifies the signature
    # try:
    #     # Verify the signature
    #     rsa_public_key_bytes.verify(
    #         sender_signed_DH_public_key,
    #         sender_DH_public_key_bytes,  # The original message that was signed
    #         padding.PSS(
    #             mgf=padding.MGF1(hashes.SHA256()),
    #             salt_length=padding.PSS.MAX_LENGTH,
    #         ),
    #         hashes.SHA256(),
    #     )
    #     print("Signature is valid.")
    # except InvalidSignature:
    #     print("Signature is invalid.")

    # Revert the public key from sender.py that is in bytes back to an integer
    sender_DH_public_key = int.from_bytes(sender_DH_public_key_bytes, 'big')
    print("Sender.py's Public Key:", sender_DH_public_key)

    # Compute shared secret key
    shared_secret = compute_shared_secret(sender_DH_public_key, receiver_DH_private_key, p)
    print("Shared Secret Receiver.py:", shared_secret)

    # Send the shared secret to sender.py
    client_socket.sendall(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'))

    # Recieve the shared secret from reciever.py and turn it back into an integer
    sender_shared_secret = int.from_bytes(client_socket.recv(1024), 'big')

    # Compare shared secrets to make sure they match and update shared_secrets_match
    if shared_secret == sender_shared_secret:
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

#open socket to recieve message
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    while True:
        try:
            client_socket.connect((senderIP, serverPort))  # Try to connect to the server
            break  # If the connection is successful, break out of the loop
        except ConnectionRefusedError:
            print("Connection failed. Trying again in 5 seconds...")
            time.sleep(5)  # Wait for 5 seconds before trying again
    # Recieve the encrypted message from sender.py
    encrypted_message = client_socket.recv(1024)
    # Recieve the IV from sender.py
    iv = client_socket.recv(1024)

    # Decrypt the message
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    print("Decrypted Message:", decrypted_message.decode())

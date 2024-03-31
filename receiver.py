#Establish a shared secret with Diffie-Hellman key exchange

#import the necessary libraries
import time
import struct
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


    # Libraries for TCP socket API
import socket

# Global Variables
p = 23
g = 5

shared_secrets_match = False
# 10.0.0.92 is my PC, 10.0.0.97 is my Mac
senderIP = '10.0.0.92' # Set this to the IP of the computer running the sender.py code
serverPort = 50101 # Set this to the port number the sender.py code is listening on

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
        raise ConnectionError("Connection closed by peer")
    length = struct.unpack('!I', length_prefix)[0]
    
    # Read exactly 'length' bytes
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
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
            print("Connection failed. Trying again in 5 seconds...")
            time.sleep(5)  # Wait for 5 seconds before trying again
    print("Connection Succesful")


    # Send receiver.py's DH public key to sender.py, will be sent in bytes
    send_with_length_prefix(client_socket, receiver_DH_public_key_bytes)
    print("Sent Receiver.py's Public Key:", receiver_DH_public_key_bytes)

    # Receive sender.py's RSA public key
    rsa_public_key_bytes = recv_with_length_prefix(client_socket)
    print("received RSA public key")
    # Receive sender.py's DH public key
    sender_DH_public_key_bytes = recv_with_length_prefix(client_socket)
    print("Received Sender.py's Public Key:")
    # Receive sender.py's RSA signed DH public key
    sender_signed_DH_public_key = recv_with_length_prefix(client_socket)
    print("Received Sender.py's Signed Public Key:")

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
        print("Signature is valid.")
    except InvalidSignature:
        print("Signature is invalid.")

    # Revert the public key from sender.py that is in bytes back to an integer
    sender_DH_public_key = int.from_bytes(sender_DH_public_key_bytes, 'big')

    # Compute shared secret key
    shared_secret = compute_shared_secret(sender_DH_public_key, receiver_DH_private_key, p)
    print("Shared Secret from Receiver.py:", shared_secret)

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

# Print the AES key
print("AES Key:", aes_key)

# Receive data until there's no more to receive (for the file)
time.sleep(3) # Wait for 3 seconds to ensure that the sender has sent the file
chunks = []
while True:
    chunk = client_socket.recv(4096)  # Adjust buffer size as necessary
    if not chunk:
        break  # No more data to receive
    chunks.append(chunk)
encrypted_message = b''.join(chunks)

# Receive the IV
iv = client_socket.recv(4096)
print("Received IV:", iv)

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

print("Decrypted Message:", decrypted_message.decode())

# Close the socket
client_socket.close()
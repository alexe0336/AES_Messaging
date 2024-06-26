#Establish a shared secret with Diffie-Hellman key exchange
# Alex Espinoza

#import the necessary libraries
import struct
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Global variables
p = 23 # Prime number, you can change just make sure you also change it in receiver.py
g = 5 # Generator, you can change just make sure you also change it in receiver.py

shared_secrets_match = False

file_path = 'input.txt' # Name and path of file to be encrypted
encrypted_file_path = 'encrypted.txt' # Name and path of where it will save file after encryption
iv = b'IVkeyneedstobe16'  # Hardcoded IV key, must be 16 bytes

port = 50101 # Change port number to whatever you want, just make sure it matches the receiver.py port number

#Introduction print statement
print("\nYou are currently running the sender.py file. This file sends the encrypted file to the receiver.py file for decryption.")

# Function to generate Diffie-Hellman private key
def generate_private_key(p):
    from random import randint
    # Generate a private key less than p
    return randint(2, p-2)

# Function to generate Diffie-Hellman public key
def generate_public_key(g, private_key, p):
    # public_key = g^private_key mod p
    return int(pow(g, private_key, p))

# Function to compute shared secret key, requires other party's public key
def compute_shared_secret(other_public_key, private_key, p):
    # shared_secret = other_public_key^private_key mod p
    return int(pow(other_public_key, private_key, p))

# Function that sets the receive length of the data incoming
def send_with_length_prefix(client_socket, data):
    # Prefix each message with its length (32-bit integer, 4 bytes)
    length_prefix = struct.pack('!I', len(data))
    client_socket.sendall(length_prefix + data)

# Function that sends the data with a length prefix
def recv_with_length_prefix(client_socket):
    # Read the length prefix (32-bit integer, 4 bytes)
    length_prefix = client_socket.recv(4)
    if not length_prefix:
        raise ConnectionError("Connection closed by peer")
    length = struct.unpack('!I', length_prefix)[0]
    
    # Read exactly 'length' bytes
    data = b''
    while len(data) < length:
        chunk = client_socket.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        data += chunk
    return data

# Generate RSA key pair
private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

#Create the RSA public key
public_key_rsa = private_key_rsa.public_key() 

#convert the RSA public key to bytes so it can be sent
public_key_rsa_bytes = public_key_rsa.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Generate Diffie-Hellman private key
sender_DH_private_key = generate_private_key(p)

# Generate Diffie-Hellman public key
sender_DH_public_key = generate_public_key(g, sender_DH_private_key, p)

# Public key must be converted to bytes before it can be sent
sender_DH_public_key_bytes = sender_DH_public_key.to_bytes((sender_DH_public_key.bit_length() + 7) // 8, 'big')

#sender.py RSA signs the DH public key
signed_DH_public_key_bytes = private_key_rsa.sign(
    sender_DH_public_key_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', port))  # Listen on port 50101
server_socket.listen()

print("\nServer waiting for receiver.py to be available...")
conn, addr = server_socket.accept()

with conn:
    print('\nConnected by', addr)

    # Get receiver.py's DH public key
    receiver_DH_public_key = recv_with_length_prefix(conn)

    # Send the RSA Public key
    send_with_length_prefix(conn, public_key_rsa_bytes)

    # Send sender.py's DH public key
    send_with_length_prefix(conn, sender_DH_public_key_bytes)

    # Send RSA signed DH public key
    send_with_length_prefix(conn, signed_DH_public_key_bytes)

    # Reverting the public key from bytes back to an integer
    receiver_DH_public_key = int.from_bytes(receiver_DH_public_key, 'big')

    #Compute the shared secret
    shared_secret = compute_shared_secret(receiver_DH_public_key, sender_DH_private_key, p)

    # Send the shared secret to receiver.py
    send_with_length_prefix(conn, (shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')))

    # Receive the shared secret from receiver.py and turn it back into an integer
    receiver_shared_secret = recv_with_length_prefix(conn)
    receiver_shared_secret = int.from_bytes(receiver_shared_secret, 'big')

    # Compare shared secrets to make sure they match and update shared_secrets_match
    if shared_secret == receiver_shared_secret:
        shared_secrets_match = True
        print(f"\nShared secrets match: Sender.py secret_{shared_secret} = Receiver.py secret_{receiver_shared_secret}")
    else:
        shared_secrets_match = False
        print(f"\nShared secrets do not match: Sender.py secret_{shared_secret} != Receiver.py secret_{receiver_shared_secret}")

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

# Encrypting the file with the AES key
key = aes_key

# #Create a function to encrypt the file
def encrypt_file(file_path, encrypted_file_path, key, iv):
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as infile:
        with open(encrypted_file_path, 'wb') as outfile:

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

try:
    conn, addr = server_socket.accept()
    with conn:
        try:
            # Sending the encrypted file in chunks
            with open(encrypted_file_path, 'rb') as file:
                data = file.read()
                send_with_length_prefix(conn,data)
            print("\nEncrypted file sent")

            # Sending IV (assuming it's not too large)         
            conn.sendall(iv)
            print("\nIV sent", iv)

        except Exception as e:
            print(f"\nAn error occurred: {e}")

        finally:
            # Clean up
            if conn:
                conn.close()
                print("\n Connection closed, Program finished.")
except Exception as e:
    print(f"\nAn error occurred when accepting the connection: {e}")
finally:
    if server_socket:
        server_socket.close()
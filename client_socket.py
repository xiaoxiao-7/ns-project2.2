import socket
import sys
import struct
import os
import ssl
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
# AES libraries in CBC mode
from cryptography.hazmat.primitives.ciphers import base, algorithms, modes
import base64
from Crypto.Cipher import AES
from Crypto import Random
from cryptography.hazmat.primitives import padding as padding2
from cryptography import x509
from cryptography.x509.oid import NameOID
#from cryptography.x509.base import sign

# Phase 0: Generate client RSA key
# Produce client private key and export as PEM file
# 1. Generate the RSA Private Key ( the RSA PRivate key is a object containing both private key and public key )
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024,  backend=default_backend())
# 2. Transform the RSA Private key to it's PEM format
pem = client_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
pem.splitlines()[0]
# 3. Write the PEM format into the PEM file
client_private_key_path = 'client_private.pem'
client_private = open(client_private_key_path,'w+')
client_private.write(str(pem, 'utf-8'))
client_private.close()

# Produce client public key and export as PEM file
# 1. Get the RSA Public Key from the object - RSA PRivate key
client_public_key = client_private_key.public_key()
# 2. Transform the RSA Public key to it's PEM format
pem = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
pem.splitlines()[0]
# 3. Write the PEM format into the PEM file
client_public_key_path = 'client_public.pem'
client_public = open(client_public_key_path,'w+')
client_public.write(str(pem, 'utf-8'))	
client_public.close()

# Phase 1: Connection between client and CA
IP_OF_SERVER, PORT_OF_SERVICE = "140.113.194.88", 20000
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	# Connect to the server
	sock.connect((IP_OF_SERVER, PORT_OF_SERVICE))
	
	# Send the student ID to CA
	# 1. Send the size in byte of student ID to CA
	msg_size = len("0540015")
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall( byte_msg_size )
	# 2. Send the student ID string to CA
	sock.sendall(bytes("0540015", 'utf-8'))

	# Receive Hello from CA
	# 1. Receive the size in byte of "hello" from CA
	hello_size = struct.unpack("i", sock.recv(4))
	# 2. Receive "hello" from Server
	hello_received = str(sock.recv(int(hello_size[0])), "utf-8")
	# 3. Write "Received Hello" and store it. 
	print("handshake message from server:" + hello_received)
	hello_received_path = open('hello.txt','w+')
	hello_received_path.write(hello_received)
	hello_received_path.close()

	#public_key = csr.public_key()
	#isinstance(public_key, rsa.RSAPublicKey)

	with open('client_private.pem','rb') as client_private:
	# Send the Certificate Signing Request PEM file
	# 1. Generate the Certificate Signing Request PEM file
		csr = x509.CertificateSigningRequestBuilder()
		csr = csr.subject_name(x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, u'0540015'),
		]))
		csr = csr.add_extension(x509.SubjectAlternativeName([
				# Describe what sites we want this certificate for.
				#x509.DNSName(u"140.113.194.88:20500"),
				#x509.DNSName(u"www.140.113.194.88:20500")
				#x509.DNSName(u"www.140.113.194.88:20500"),
			]),
			critical=False,)
		print(type(csr))
		#print(type(csr))
		# Sign the CSR with our private key.
		#with open('client_private.pem','r+') as key_file:
		csr = csr.sign(client_private_key, hashes.SHA256(), default_backend())
		print(isinstance(csr, x509.CertificateSigningRequest))
		# Write our CSR out to disk.
		with open("csr.pem", "wb") as f:
			f.write(csr.public_bytes(serialization.Encoding.PEM))
	# 1. Send the size in byte of CSR to CA
	# 2. Send the CSR string to CA

	# Receive the Certificate in PEM format
	# Receive bye from CA





# Phase 2: Connection between client and GameDownloader
# Send the student ID to GameDownloader
# Receive Hello from GameDownloader
# Send the Certificate PEM file to GameDownloader
# Receive PASS from GameDownloader
# Receive AES Session Key from GameDownloader
# Receive Initial Vector from GameDownloader
# Receive Game binary from GameDownloader
# Send bye to GameDownloader






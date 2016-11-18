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
from cryptography.hazmat.primitives.ciphers import base, algorithms, modes, Cipher
import base64
from Crypto.Cipher import AES
#from Crypto import Cipher
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
	# 2. Receive "hello" from CA
	hello_received = str(sock.recv(int(hello_size[0])), "utf-8")
	# 3. Write "Received Hello" and store it. 
	print("handshake message from server:" + hello_received)
	hello_received_path = open('hello.txt','w+')
	hello_received_path.write(hello_received)
	hello_received_path.close()

	with open('client_private.pem','rb') as client_private:
	# Send the Certificate Signing Request PEM file
	# 1. Generate the Certificate Signing Request PEM file
		request = x509.CertificateSigningRequestBuilder()
		request = request.subject_name(x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, u'0540015'),
		]))
		request = request.add_extension(x509.SubjectAlternativeName([
				# Describe what sites we want this certificate for.
				#x509.DNSName(u"140.113.194.88:20500"),
				#x509.DNSName(u"www.140.113.194.88:20500")
				#x509.DNSName(u"www.140.113.194.88:20500"),
			]),
			critical=False,)
		# Sign the CSR with our private key.
		#with open('client_private.pem','r+') as key_file:
		csr = request.sign(client_private_key, hashes.SHA256(), default_backend())
		#print(isinstance(csr, x509.CertificateSigningRequest))
		# Write our CSR out to disk.
		with open("client_csr.pem", "wb") as f:
			f.write(csr.public_bytes(serialization.Encoding.PEM))
			client_csr = csr.public_bytes(serialization.Encoding.PEM)
	# 1. Send the size in byte of CSR to CA
	client_csr_size = len(client_csr)
	byte_client_csr_size = struct.pack("i", client_csr_size)
	sock.sendall( byte_client_csr_size )
	# 2. Send the CSR string to CA
	sock.sendall(client_csr)

	# Receive the Certificate in PEM format
	# 1. Receive the size of the Certificate from CA
	certificate_size = struct.unpack("i", sock.recv(4))
	# 2. Receive the Certificate from CA
	certificate_received = sock.recv(int(certificate_size[0]))
	# 3. Write the Certificate from CA and store it
	certificate_received_path = open('certificate_CA.pem','wb')
	certificate_received_path.write(certificate_received)
	certificate_received_path.close()

	# Receive bye from CA
	# 1. Receive the size in byte of bye-message from CA
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive bye-message from CA
	received = str(sock.recv(int(msg_size[0])), "utf-8")
	print("handshake message from CA:", received)

# Phase 2: Connection between client and GameDownloader
IP_OF_SERVER, PORT_OF_SERVICE = "140.113.194.88", 20500
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	# Connect to the server
	sock.connect((IP_OF_SERVER, PORT_OF_SERVICE))
	
	# Send the student ID to GameDownloader/Server
	# 1. Send the size in byte of student ID to GameDownloader/Server
	msg_size = len("0540015")
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall( byte_msg_size )
	# 2. Send the student ID string to GameDownloader/Server
	sock.sendall(bytes("0540015", 'utf-8'))

	# Receive Hello from GameDownloader/Server
	# 1. Receive the size in byte of "hello" from GameDownloader/Server
	hello_2_size = struct.unpack("i", sock.recv(4))
	# 2. Receive "hello" from GameDownloader/Server
	hello_2_received = str(sock.recv(int(hello_2_size[0])), "utf-8")
	# 3. Write "Received Hello" and store it. 
	print("handshake message from server:" + hello_2_received)
	hello_2_received_path = open('hello_2.txt','w+')
	hello_2_received_path.write(hello_received)
	hello_2_received_path.close()
	# Send the Certificate PEM file to GameDownloader/Server
	# 1. Read the Certificate's PEM file
	certificate_received_path = 'certificate_CA.pem'
	certificate_CA = open(certificate_received_path, 'r+')
	certificate_send_to_server = certificate_CA.read()
	# 2. Send the size in byte of Certificate's PEM file to GameDownloader/Server
	certificate_send_to_server_size = len(certificate_send_to_server)
	byte_certificate_send_to_server_size = struct.pack("i", certificate_send_to_server_size)
	sock.sendall( byte_certificate_send_to_server_size )
	# 3. Send Certificate's PEM file to GameDownloader/Server
	sock.sendall(bytes(certificate_send_to_server, 'utf-8'))
	certificate_CA.close()
	# Receive PASS from GameDownloader
	# 1. Receive the size in byte of PASS from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive PASS from Server
	received = str(sock.recv(int(msg_size[0])), "utf-8")
	print("handshake message from server:", received)

	# Receive AES Session Key from GameDownloader
	# 1. Receive the size in byte of AES Session Key from Server
	AES_Session_key_size = struct.unpack("i", sock.recv(4))
	# 2. Receive AES Session Key from Server
	Encrypted_AES_Session_key = sock.recv(int(AES_Session_key_size[0]))
	# 3. Decrypt AES_Session_Key_Received 
	with open('client_private.pem','r+') as key_file:
		private_key = serialization.load_pem_private_key(bytes(key_file.read(),"utf-8"), password=None, backend=default_backend())
		decrypted_AES_Session_key_received = private_key.decrypt(Encrypted_AES_Session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))	
	# 4. Write the AES Session Key and store it. 
		AES_Session_key_path = open('AES_Session_key.pem','wb')
		AES_Session_key_path.write(decrypted_AES_Session_key_received)
		AES_Session_key_path.close()

	# Receive Initial Vector from GameDownloader
	# 1. Receive the size in byte of IV from Server
	IV_size = struct.unpack("i", sock.recv(4))
	# 2. Receive Encrypted IV from Server
	Encrypted_IV = sock.recv(int(IV_size[0]))
	# 3. Decrypt AES_Session_Key_Received 
	with open('client_private.pem','r+') as key_file:
		private_key = serialization.load_pem_private_key(bytes(key_file.read(),"utf-8"), password=None, backend=default_backend())
		decrypted_IV_received = private_key.decrypt(Encrypted_IV, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))	
	# 4. Write the AES Session Key and store it. 
		#print(decrypted_IV_received)
		IV_path = open('IV.txt','wb')
		IV_path.write(decrypted_IV_received)
		IV_path.close()

	# Receive Game binary from GameDownloader
	# 1. Receive the size of the Game binary from server
	game_binary_size = struct.unpack("i", sock.recv(4))
	#print(game_binary_size)
	#print(int(game_binary_size[0]))
	# 2. Receive the Game binary from server
	game_binary_received = bytes()
	while len(game_binary_received) < int(game_binary_size[0]):
		game_binary_received += sock.recv(int(game_binary_size[0]))
		print(len(game_binary_received))
	# 2. Decrypt the Game binary with AES session key
	with open('AES_Session_key.pem','rb') as AES_Session_key:
		with open('IV.txt', 'rb') as IV: 
			#padder = padding2.PKCS7(128).padder()
			#padded_message = padder.update(secret_message_received)
			#padded_message += padder.finalize()
			cipher = Cipher(algorithms.AES(decrypted_AES_Session_key_received), modes.CBC(decrypted_IV_received), backend=default_backend())
			decryptor = cipher.decryptor()
			#print(decryptor.update(padded_message) + decryptor.finalize())
	# 3. write the secret message ans store it
			#decrypted_secret_message = decryptor.update(padded_message) + decryptor.finalize()
			decrypted_game_binary = decryptor.update(game_binary_received)
			#unpadder = padding2.PKCS7(128).unpadder()
			#unpadder_game_binary = unpadder.update(decrypted_game_binary)
			game_binary_path = open('game_binary.bin','wb')
			game_binary_path.write(decrypted_game_binary)
			game_binary_path.close()
			#print(str(unpadder_secret_message))

	# Send bye to GameDownloader
	# 1. Send the size in byte of bye to Server/Gamedownloader
	msg_size = len("bye")
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall( byte_msg_size )
	# 2. Send the student ID string to CA
	sock.sendall(bytes("bye", 'utf-8'))
	#print(msg_size)


# Reverse the binary file into  assembly file






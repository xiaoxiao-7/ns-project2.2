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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from Crypto.Cipher import AES
from Crypto import Random
from cryptography.hazmat.primitives import padding as padding2
from cryptography import x509
from 
#from cryptography.x509 import NameOID

instance_test = x509._attributes
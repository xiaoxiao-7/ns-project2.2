from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
# Provide various details about who we are.
x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
])).add_extension(
x509.SubjectAlternativeName([
# Describe what sites we want this certificate for.
x509.DNSName(u"mysite.com"),
x509.DNSName(u"www.mysite.com"),
x509.DNSName(u"subdomain.mysite.com"),
]),
critical=False,
# Sign the CSR with our private key.
).sign(key, hashes.SHA256(), default_backend())
# Write our CSR out to disk.
with open("path/to/csr.pem", "wb") as f:
	f.write(csr.public_bytes(serialization.Encoding.PEM))


	# Generate CSR
def generateCSR(nodename):
    csrfile = 'csr.pem'
    req = crypto.X509Req()
    # Return an X509Name object representing the subject of the certificate.
    req.get_subject().CN = nodename
    #req.get_subject().countryName = 'xxx'
    #req.get_subject().stateOrProvinceName = 'xxx'
    #req.get_subject().localityName = 'xxx'
    #req.get_subject().organizationName = 'xxx'
    #req.get_subject().organizationalUnitName = 'xxx'
    # Set the public key of the certificate to pkey.
    with open('client_public.pem','rb') as client_public:
    	req.set_pubkey(client_public)
    # Sign the certificate, using the key pkey and the message digest algorithm identified by the string digest.
    	req.sign(client_public, "sha256")
    # Dump the certificate request req into a buffer string encoded with the type type.
    if os.path.exists(csrfile):
        print "Certificate file exists, aborting."
        print " ", csrfile
        sys.exit(1)
    else:
        f = open('incommon.csr', "w")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        f.close()

#Call key & CSR functions
key = generateKey(TYPE_RSA,2048)
# Needs to take input from user.
generateCSR('test.test.edu')
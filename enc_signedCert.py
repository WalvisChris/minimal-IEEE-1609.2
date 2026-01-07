from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der import encoder
from lib.asn1.signedCertASN1 import *
from lib.TerminalInterface import *
import time
import os

# Paths
PRIVATE_KEY_PATH = "keys/private_key.pem"
OUTPUT_PATH = "messages/msg_signedCert.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()
terminal.startTimer()
times = []

# Variables
payload_bytes = payload.encode('utf-8')

PSID = 0x20
GENERATION_TIME = int(time.time() * 1_000_000)
EXPIRY_TIME = GENERATION_TIME + 10_000_000
times.append(("HeaderInfo Metadata", terminal.getTimeStamp()))

with open(PRIVATE_KEY_PATH, "rb") as key_file:
    PRIVATE_KEY = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
times.append(("Read Private Key", terminal.getTimeStamp()))

# === ToBeSignedData ===
tbs_data = ToBeSignedData()
tbs_data['payload'] = SignedDataPayload()
tbs_data['payload']['data'] = payload_bytes
tbs_data['headerInfo'] = HeaderInfo()
tbs_data['headerInfo']['psid'] = PSID
tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME
times.append(("ToBeSignedData inpakken", terminal.getTimeStamp()))

# === VerifyKeyIndicator ===
verify_key = VerificationKeyIndicator()

PUBLIC_KEY = PRIVATE_KEY.public_key()
numbers = PUBLIC_KEY.public_numbers()
x_bytes = numbers.x.to_bytes(32, 'big')
y_bytes = numbers.y.to_bytes(32, 'big')

verify_key['ecdsaNistP256'] = EccP256CurvePoint()
verify_key['ecdsaNistP256']['uncompressed'] = UncompressedP256()
verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes
times.append(("Public Key Numbers als X, Y", terminal.getTimeStamp()))

# === ToBeSignedCertificate ===
tbs_cert = ToBeSignedCertificate()
tbs_cert['id'] = CertificateId()
tbs_cert['id']['name'] = "pijlwagen1234" # PLACEHOLDER
tbs_cert['cracaId'] = HashedId3(b'\x01\x02\x03') # PLACEHOLDER
tbs_cert['crlSeries'] = 0 # PLACEHOLDER
tbs_cert['validityPeriod'] = ValidityPeriod()
tbs_cert['validityPeriod']['start'] = int(time.time())
tbs_cert['validityPeriod']['duration'] = Duration()
tbs_cert['validityPeriod']['duration']['hours'] = 24
tbs_cert['verifyKeyIndicator'] = verify_key
times.append(("ToBeSignedCertificate inpakken", terminal.getTimeStamp()))

# === Signer ===
signer = SignerIdentifier()
signer['certificate'] = Certificate()
signer['certificate']['version'] = 1
signer['certificate']['type'] = CertificateType(0)
signer['certificate']['issuer'] = IssuerIdentifier()
signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
signer['certificate']['toBeSignedCert'] = tbs_cert

cert_tbs_der = encoder.encode(tbs_cert)
cert_signature = PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))

signer['certificate']['signature'] = cert_signature
times.append(("Signer inpakken", terminal.getTimeStamp()))

# === Signature ===
signature = Signature()

tbs_der = encoder.encode(tbs_data)
times.append(("ToBeSignedData ASN1 Encoding", terminal.getTimeStamp()))

digest = hashes.Hash(hashes.SHA256())
digest.update(tbs_der)
hash_value = digest.finalize()
times.append(("ToBeSignedData Hashing", terminal.getTimeStamp()))

signature_der = PRIVATE_KEY.sign(
    hash_value, ec.ECDSA(Prehashed(hashes.SHA256()))
)
r, s = decode_dss_signature(signature_der)

signature['ecdsaNistP256Signature'] = EcdsaP256Signature()
signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')
times.append(("Signature als R, S", terminal.getTimeStamp()))

# === SignedData ===
signed_data = SignedData()
signed_data['hashId'] = HashAlgorithm(0)
signed_data['tbsData'] = tbs_data
signed_data['signer'] = signer
signed_data['signature'] = signature
times.append(("SignedData inpakken", terminal.getTimeStamp()))

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = Ieee1609Dot2Content()
ieee_data['content']['signedData'] = signed_data
times.append(("Ieee1609Dot2Data inpakken", terminal.getTimeStamp()))

# Send
final_bytes = encoder.encode(ieee_data)
times.append(("Final Encoding", terminal.getTimeStamp()))
total = terminal.getTime()

with open(OUTPUT_PATH, "wb") as f:
    f.write(final_bytes)

# Result
terminal.printASN1(ieee_data)
_ = f"bericht opgeslagen in {OUTPUT_PATH}"
terminal.text(text=_)

# Printing
terminal.empty()
terminal.logTimes(times=times, total=total)
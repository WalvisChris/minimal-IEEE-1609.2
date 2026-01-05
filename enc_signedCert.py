from lib.TerminalInterface import *
from lib.asn1.signedCertASN1 import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from pyasn1.codec.der import encoder
import time
import os

# Paths
PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"
OUTPUT_PATH = "messages/msg_signedCert.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()

# Variables
payload_bytes = payload.encode('utf-8')
PSID = 0x20
GENERATION_TIME = int(time.time() * 1_000_000)
EXPIRY_TIME = GENERATION_TIME + 10_000_000

with open(PRIVATE_KEY_PATH, "rb") as key_file:
    PRIVATE_KEY = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# === SignedDataPayload ===
signed_payload = SignedDataPayload()
signed_payload['data'] = payload_bytes

# === HeaderInfo ===
header = HeaderInfo()
header['psid'] = PSID
header['generationTime'] = GENERATION_TIME
header['expiryTime'] = EXPIRY_TIME

# === ToBeSignedData ===
tbs_data = ToBeSignedData()
tbs_data['payload'] = signed_payload
tbs_data['headerInfo'] = header

# === CertificateId ===
certId = CertificateId()
certId['name'] = "demo_pijlwagen"

# === Duration ===
duration = Duration()
duration['hours'] = 24

# === ValidityPeriod ===
valPeriod = ValidityPeriod()
valPeriod['start'] = int(time.time())
valPeriod['duration'] = duration

# === ToBeSignedCertificate ===
tbs_cert = ToBeSignedCertificate()
tbs_cert['id'] = certId
tbs_cert['cracaId'] = HashedId3(b'\x01\x02\x03')
tbs_cert['crlSeries'] = 0
tbs_cert['validityPeriod'] = valPeriod

# === IssuerIdentifier ===
issuer = IssuerIdentifier()
issuer['sha256AndDigest'] = os.urandom(8) # placeholder

# === Certificate ===
cert = Certificate()
cert['version'] = 1
cert['type'] = CertificateType(0)
cert['issuer'] = issuer
cert['toBeSignedCert'] = tbs_cert

cert_tbs_der = encoder.encode(tbs_cert)
cert_signature = PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))

cert['signature'] = cert_signature

# === HASHING ===
tbs_der = encoder.encode(tbs_data)
digest = hashes.Hash(hashes.SHA256())
digest.update(tbs_der)
hash_value = digest.finalize()

# === SIGNING ===
signature_der = PRIVATE_KEY.sign(
    hash_value, ec.ECDSA(Prehashed(hashes.SHA256()))
)
r, s = decode_dss_signature(signature_der)

# === EccP256CurvePoint ===
curve_point = EccP256CurvePoint()
curve_point['x-only'] = r.to_bytes(32, 'big')

ecdsa_sig = EcdsaP256Signature()
ecdsa_sig['rSig'] = curve_point
ecdsa_sig['sSig'] = s.to_bytes(32, 'big')

# === Signature ===
signature = Signature()
signature['ecdsaNistP256Signature'] = ecdsa_sig

# === SignerIdentifier ===
signer = SignerIdentifier()
signer['certificate'] = cert

# === SignedData ===
signed_data = SignedData()
signed_data['hashId'] = HashAlgorithm(0)
signed_data['tbsData'] = tbs_data
signed_data['signer'] = signer
signed_data['signature'] = signature

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()
ieee_content['signedData'] = signed_data

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = ieee_content

# === TESTING ===
terminal.printASN1(ieee_data)

# === DER ENCODING ===
final_bytes = encoder.encode(ieee_data)

# === SEND MESSAGE ===
with open(OUTPUT_PATH, "wb") as f:
    f.write(final_bytes)

_ = f"bericht opgeslagen in {OUTPUT_PATH}"
terminal.text(text=_)
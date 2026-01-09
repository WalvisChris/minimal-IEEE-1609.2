from lib.asn1.signedCertASN1 import *
from lib.TerminalInterface import *
from pyasn1.codec.der import encoder, decoder
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
import time

# Paths
INPUT_PATH = "messages/msg_signedCert.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()

# Checks
certTimeCheck = False
timeCheck = False
sigCheck = False
certCheck = False

# Variables
with open(INPUT_PATH, "rb") as f:
    encoded_data = f.read()

decoded_data, _ = decoder.decode(encoded_data, asn1Spec=Ieee1609Dot2Data())

# === PRINT ===
_ = f"bericht opgehaald uit {INPUT_PATH}"
terminal.text(text=_)
terminal.printASN1(decoded_data)

# === Uitpakken ===
ieee_content = decoded_data['content']
signed_data = ieee_content['signedData']

tbs_data = signed_data['tbsData']
header = tbs_data['headerInfo']
payload = tbs_data['payload']['data']

signer_cert = signed_data['signer']['certificate']
tbs_cert = signer_cert['toBeSignedCert']

# === Certificate Tijdscontrole ===
start = int(tbs_cert['validityPeriod']['start']) # Time32, in seconden
duration_hours = int(tbs_cert['validityPeriod']['duration']['hours']) # aantal uren
expiry = start + duration_hours * 3600  # omzet naar seconden
now = int(time.time())

if now > expiry:
    certTimeMsg = "Certificaat is verlopen!"
    pass
elif now < start:
    certTimeMsg = "Certificaat komt uit de toekomst!"
    pass
else:
    certTimeMsg = "Geldig Certificaat."
    certTimeCheck = True

# === Tijdscontrole ===
_generation = int(header['generationTime'])
_expiry = int(header['expiryTime'])
_now = int(time.time() * 1_000_000)
if _now > _expiry:
    timeMsg = "Bericht is verlopen!"
    pass
elif _now < _generation:
    timeMsg = "Bericht komt uit de toekomst!"
    pass
else:
    timeMsg = "Geldig bericht."
    timeCheck = True

# === Public key ophalen ===
verify_key_indicator = tbs_cert['verifyKeyIndicator']
ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']

x_bytes = bytes(ecc_point['x'])
y_bytes = bytes(ecc_point['y'])

x = int.from_bytes(x_bytes, 'big')
y = int.from_bytes(y_bytes, 'big')

public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
cert_public_key = public_numbers.public_key(default_backend())

# === Signature uitpakken ===
signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
r_bytes = bytes(signature_asn1['r'])
s_bytes = bytes(signature_asn1['s'])

r = int.from_bytes(r_bytes, 'big')
s = int.from_bytes(s_bytes, 'big')

signature_der = encode_dss_signature(r, s)

# === Hash berekenen ===
tbs_der = encoder.encode(tbs_data)
digest = hashes.Hash(hashes.SHA256())
digest.update(tbs_der)
hash_value = digest.finalize()

# === Signature Validatie ===
try:
    cert_public_key.verify(
        signature_der,
        hash_value,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )
    sigMsg="Geldige Handtekening!"
    sigCheck = True
except Exception as e:
    sigMsg = f"Ongeldige Handtekening! {e}"
    pass

# === Certificate Validatie ===
cert_signature = bytes(signer_cert['signature'])
cert_tbs_der = encoder.encode(tbs_cert)

try:
    cert_public_key.verify(
        cert_signature,
        cert_tbs_der,
        ec.ECDSA(hashes.SHA256())
    )
    certMsg = "Geldig Certificaat!"
    certCheck = True
except Exception as e:
    certMsg = f"Ongeldig Certificaat! {e}"
    pass

# === RAPPORT ===
terminal.logValidation(cert_time=certTimeCheck, time=timeCheck, sig=sigCheck, cert=certCheck)
terminal.logDetailedValidation(certTimeMsg=certTimeMsg, timeMsg=timeMsg, sigMsg=sigMsg, certMsg=certMsg)
from lib.TerminalInterface import *
from lib.asn1.signedASN1 import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from pyasn1.codec.der import encoder
import time

# Paths
PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"
OUTPUT_PATH = "messages/msg_signed.txt"

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
signed_payload['data'] = univ.OctetString(payload_bytes)

# === HeaderInfo ===
header = HeaderInfo()
header['psid'] = PSID
header['generationTime'] = GENERATION_TIME
header['expiryTime'] = EXPIRY_TIME

# === ToBeSignedData ===
tbsData = ToBeSignedData()
tbsData['payload'] = signed_payload
tbsData['headerInfo'] = header

# === DER ENCODING ===
tbs_der = encoder.encode(tbsData)

# === HASHING ===
digest = hashes.Hash(hashes.SHA256())
digest.update(tbs_der)
hash_value = digest.finalize()

# === ECDSA SIGNING ===
signature_der = PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
r, s = decode_dss_signature(signature_der)

# === DER -> raw r||s ===
r_bytes = r.to_bytes(32, 'big')
s_bytes = s.to_bytes(32, 'big')

# === CurvePoint ===
r_point = EccP256CurvePoint()
r_point['x-only'] = r_bytes

# === ECDSA Signature ===
ecdsa_sig = EcdsaP256Signature()
ecdsa_sig['rSig'] = r_point
ecdsa_sig['sSig'] = s_bytes

# === Signature ===
signature = Signature()
signature['ecdsaNistP256Signature'] = ecdsa_sig

# === SignerIdentifier ===
signer = SignerIdentifier()
signer['self'] = univ.OctetString('demo')

# === SignedData ===
signed_data = SignedData()
signed_data['hashId'] = HashAlgorithm('sha256')
signed_data['tbsData'] = tbsData
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
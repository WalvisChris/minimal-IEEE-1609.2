from pyasn1.codec.der import encoder, decoder
from lib.minimalASN1 import *
from lib.TerminalInterface import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives import serialization
import time

# Paths
PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"
INPUT_PATH = "messages/msg_signed.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()

# Variables
with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

with open(INPUT_PATH, "rb") as g:
    encoded_data = g.read()

decoded_data, _ = decoder.decode(encoded_data, asn1Spec=Ieee1609Dot2Data())

# === Print ===
_ = f"bericht opgehaald uit {INPUT_PATH}"
terminal.text(text=_)
terminal.printASN1(decoded_data)

# === Vind ToBeSignedData ===
ieee_content = decoded_data['content']
signed_data = ieee_content['signedData']
tbsData = signed_data['tbsData']
header = tbsData['headerInfo']

# === Bereken Hash ===
tbs_der = encoder.encode(tbsData)
digest = hashes.Hash(hashes.SHA256())
digest.update(tbs_der)
hash_value = digest.finalize()

# === Signature Reconstueren ===
ecdsa_sig = signed_data['signature']['ecdsaNistP256Signature']
r_bytes = bytes(ecdsa_sig['rSig']['x-only'])
s_bytes = bytes(ecdsa_sig['sSig'])
r = int.from_bytes(r_bytes, 'big')
s = int.from_bytes(s_bytes, 'big')
signature_der = encode_dss_signature(r, s)

# === Verificatie met Public Key ===
try:
    PUBLIC_KEY.verify(signature_der, hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
    terminal.demoLog(title="Signature validation", text="Geldig", text_color="green")
except Exception:
    terminal.demoLog(title="Signature validation", text="Ongeldig", text_color="red")

# === Tijdscontrole ===
_generation = int(header['generationTime'])
_expiry = int(header['expiryTime'])
_now = int(time.time() * 1_000_000)
if _now > _expiry:
    terminal.demoLog(title="Tijdcontrole", text="Bericht verlopen!", text_color="red")
elif _now < _generation:
    terminal.demoLog(title="Tijdcontrole", text="Bericht uit de toekomst!", text_color="red")
else:
    terminal.demoLog(title="Tijdcontrole", text="Geldig bericht.", text_color="green")
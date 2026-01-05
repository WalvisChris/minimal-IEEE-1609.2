from lib.asn1.signedCertASN1 import *
from lib.TerminalInterface import *
from pyasn1.codec.der import encoder, decoder
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import time

# Paths
PUBLIC_KEY_PATH = "keys/public_key.pem"
INPUT_PATH = "messages/msg_signedCert.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()

# Variables
with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

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
    terminal.demoLog(title="Certificaat Tijdcontrole", text="Bericht verlopen!", text_color="red")
elif now < start:
    terminal.demoLog(title="Certificaat Tijdcontrole", text="Bericht uit de toekomst!", text_color="red")
else:
    terminal.demoLog(title="Certificaat Tijdcontrole", text="Geldig bericht.", text_color="green")

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

# === Certificate Validatie ===


# === Signature Validatie ===
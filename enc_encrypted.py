from lib.TerminalInterface import *
from lib.asn1.encryptedASN1 import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import encoder
import os

# Paths
PSK_PATH = "keys/psk.txt"
OUTPUT_PATH = "messages/msg_encrypted.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()

# Variables
payload_bytes = payload.encode('utf-8')

with open(PSK_PATH, "rb") as f:
    psk = f.read()

digest = hashes.Hash(hashes.SHA256())
digest.update(psk)
pskId = digest.finalize()[:8]

nonce = os.urandom(12)
aesccm = AESCCM(psk)
ciphertext = aesccm.encrypt(nonce=nonce, data=payload_bytes, associated_data=None)

# === RecipientInfo ===
recipient1 = RecipientInfo()
recipient1['pskRecipInfo'] = PreSharedKeyRecipientInfo(pskId)

# === RecipientSequence ===
recipient_seq = SequenceOfRecipientInfo()
recipient_seq.append(recipient1)

# === One28BitCcmCiphertext ===
aes128ccm = One28BitCcmCiphertext()
aes128ccm['nonce'] = nonce
aes128ccm['ccmCiphertext'] = ciphertext

# === SymmetricCiphertext ===
symmCiphertext = SymmetricCiphertext()
symmCiphertext['aes128ccm'] = aes128ccm

# === EncryptedData ===
enc_data = EncryptedData()
enc_data['recipients'] = recipient_seq
enc_data['ciphertext'] = symmCiphertext

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()
ieee_content['encryptedData'] = enc_data

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

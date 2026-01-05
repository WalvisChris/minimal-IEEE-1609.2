from lib.TerminalInterface import *
from lib.asn1.encryptedASN1 import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import encoder, decoder
import os

# Paths
PSK_PATH = "keys/psk.txt"
INPUT_PATH = "messages/msg_encrypted.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()

# Variables
with open(PSK_PATH, "rb") as f:
    psk = f.read()

with open(INPUT_PATH, "rb") as g:
    encoded_data = g.read()

decoded_data, _ = decoder.decode(encoded_data, asn1Spec=Ieee1609Dot2Data())

# === Print ===
_ = f"bericht opgehaald uit {INPUT_PATH}"
terminal.text(text=_)
terminal.printASN1(decoded_data)

# === Uitpakken ===
ieee_content = decoded_data['content']
enc_data = ieee_content['encryptedData']
_me = enc_data['recipients'][0]
ciphertext_struct = (
    decoded_data
    ['content']
    ['encryptedData']
    ['ciphertext']
    ['aes128ccm']
)
nonce = bytes(ciphertext_struct['nonce'])
ciphertext = bytes(ciphertext_struct['ccmCiphertext'])

# === PSK-ID controle ===
received_pskId = bytes(_me['pskRecipInfo'])

digest = hashes.Hash(hashes.SHA256())
digest.update(psk)
expected_pskId = digest.finalize()[:8]

if received_pskId != expected_pskId:
    terminal.demoLog(title="pskId validation", text="no match!", text_color="red")
else:
    terminal.demoLog(title="pskId validation", text="match!", text_color="green")


# === Decryptie ===
aesccm = AESCCM(psk)
try:
    plaintext = aesccm.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=None
    )
    terminal.demoLog(title="decryption", text=plaintext)
except:
    terminal.demoLog(title="decryption", text="failed.", text_color="red")
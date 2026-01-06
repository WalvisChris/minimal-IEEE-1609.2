from lib.TerminalInterface import *
from lib.asn1.encryptedASN1 import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import decoder

# Paths
PSK_PATH = "keys/psk.txt"
INPUT_PATH = "messages/msg_encrypted.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()

# Checks
encCheck = False
pskIdCheck = False

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
    pskIdMsg = "PskId Matched Niet!"
else:
    pskIdMsg = "PskId Matched!"
    pskIdCheck = True


# === Decryptie ===
aesccm = AESCCM(psk)
try:
    plaintext = aesccm.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=None
    )
    encMsg = f"gelukt: {plaintext}"
    encCheck = True
except:
    encMsg = "mislukt."

# === RAPPORT ===
terminal.logValidation(enc=encCheck, pskId=pskIdCheck)
terminal.logDetailedValidation(encMsg=encMsg, pskIdMsg=pskIdMsg)
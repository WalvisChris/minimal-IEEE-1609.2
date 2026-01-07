from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder
from lib.asn1.encryptedASN1 import *
from lib.TerminalInterface import *

# Paths
PSK_PATH = "keys/psk.txt"
OUTPUT_PATH = "messages/msg_encrypted.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()
terminal.startTimer()
times = []

# Variables
payload_bytes = payload.encode('utf-8')

with open(PSK_PATH, "rb") as f:
    psk = f.read()
times.append(("PSK ophalen", terminal.getTimeStamp()))

digest = hashes.Hash(hashes.SHA256())
digest.update(psk)
pskId = digest.finalize()[:8]
times.append(("maak PskId", terminal.getTimeStamp()))

# === Recipients ===
recipient1 = RecipientInfo()
recipient1['pskRecipInfo'] = PreSharedKeyRecipientInfo(pskId)

recipient2 = RecipientInfo()
recipient2['pskRecipInfo'] = PreSharedKeyRecipientInfo(pskId)

recipients_seq = SequenceOfRecipientInfo()
recipients_seq.append(recipient1)
recipients_seq.append(recipient2)
times.append((f"SequenceOfRecipientInfo ({len(recipients_seq)}) inpakken", terminal.getTimeStamp()))

# === SymmetricCiphertext
symmCiphertext = SymmetricCiphertext()
symmCiphertext['aes128ccm'] = One28BitCcmCiphertext()

nonce = os.urandom(12)
times.append(("nonce gemaakt", terminal.getTimeStamp()))
aesccm = AESCCM(psk)
times.append(("aesccm key gemaakt", terminal.getTimeStamp()))
ciphertext = aesccm.encrypt(nonce=nonce, data=payload_bytes, associated_data=None)
times.append(("ciphertext gemaakt", terminal.getTimeStamp()))

symmCiphertext['aes128ccm']['nonce'] = nonce
symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext

# === EncryptedData ===
enc_data = EncryptedData()
enc_data['recipients'] = recipients_seq
enc_data['ciphertext'] = symmCiphertext
times.append(("EncryptedData ingepakt", terminal.getTimeStamp()))

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = Ieee1609Dot2Content()
ieee_data['content']['encryptedData'] = enc_data
times.append(("Ieee1609Dot2Data ingepakt", terminal.getTimeStamp()))

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
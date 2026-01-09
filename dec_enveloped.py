from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder, decoder
from lib.asn1.envelopedASN1 import *
from lib.TerminalInterface import *
import time

# Paths
PSK_PATH = "keys/psk.txt"
INPUT_PATH = "messages/msg_enveloped.txt"

# --- Terminal ---
terminal = TerminalInterface()
terminal.clear()

# Checks
certTimeCheck = False
timeCheck = False
sigCheck = False
certCheck = False
encCheck = False
pskIdCheck = False

# --- Load PSK ---
with open(PSK_PATH, "rb") as f:
    psk = f.read()

# --- Load Encrypted Message ---
with open(INPUT_PATH, "rb") as g:
    encoded_data = g.read()

# --- Decode Ieee1609Dot2Data ---
decoded_data, _ = decoder.decode(encoded_data, asn1Spec=Ieee1609Dot2Data())
terminal.text(f"Bericht opgehaald uit {INPUT_PATH}")
terminal.printASN1(decoded_data)

# --- Extract EncryptedData ---
enc_data = decoded_data['content']['encryptedData']
recipient_info = enc_data['recipients'][0]
ciphertext_struct = enc_data['ciphertext']['aes128ccm']
nonce = bytes(ciphertext_struct['nonce'])
ciphertext = bytes(ciphertext_struct['ccmCiphertext'])

# --- PSK-ID Controle ---
received_pskId = bytes(recipient_info['pskRecipInfo'])
digest = hashes.Hash(hashes.SHA256())
digest.update(psk)
expected_pskId = digest.finalize()[:8]

pskIdCheck = False
if received_pskId == expected_pskId:
    pskIdMsg = "PskId Matched!"
    pskIdCheck = True
else:
    pskIdMsg = "PskId Matched Niet!"


# --- Decrypt AES-CCM ---
aesccm = AESCCM(psk)
encCheck = False
try:
    plaintext = aesccm.decrypt(nonce, ciphertext, associated_data=None)
    encMsg = f"Decryptie Gelukt: ?"
    encCheck = True
except Exception as e:
    plaintext = None
    encMsg = f"Decryptie Mislukt: {e}"

# --- SignedData Decoderen ---
if plaintext:
    signed_data, _ = decoder.decode(plaintext, asn1Spec=SignedData())
    terminal.printASN1(signed_data)
    tbs_data = signed_data['tbsData']
    header = tbs_data['headerInfo']
    payload = tbs_data['payload']['data']
    encMsg = f"Decryptie Gelukt: {payload}"

    # --- Header Time Check ---
    generation_time = int(header['generationTime'])
    expiry_time = int(header['expiryTime'])
    now = int(time.time() * 1_000_000)

    if now > expiry_time:
        timeMsg = "Bericht is verlopen!"
    elif now < generation_time:
        timeMsg = "Bericht komt uit de toekomst!"
    else:
        timeMsg = "Geldig bericht."
        timeCheck = True

    # --- Certificate Extract ---
    signer_cert = signed_data['signer']['certificate']
    tbs_cert = signer_cert['toBeSignedCert']

    # --- Certificate Time Check ---
    start = int(tbs_cert['validityPeriod']['start'])
    duration_hours = int(tbs_cert['validityPeriod']['duration']['hours'])
    expiry = start + duration_hours * 3600
    now_sec = int(time.time())
    if now_sec > expiry:
        certTimeMsg = "Certificaat is verlopen!"
    elif now_sec < start:
        certTimeMsg = "Certificaat komt uit de toekomst!"
    else:
        certTimeMsg = "Geldig Certificaat."
        certTimeCheck = True

    # --- Extract Public Key ---
    verify_key_indicator = tbs_cert['verifyKeyIndicator']
    ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
    x_bytes = bytes(ecc_point['x'])
    y_bytes = bytes(ecc_point['y'])
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    cert_public_key = public_numbers.public_key(default_backend())

    # --- Extract Signature ---
    signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
    r = int.from_bytes(bytes(signature_asn1['r']), 'big')
    s = int.from_bytes(bytes(signature_asn1['s']), 'big')
    signature_der = encode_dss_signature(r, s)

    # --- Hash ToBeSignedData ---
    tbs_der = encoder.encode(tbs_data)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()

    # --- Signature Validatie ---
    try:
        cert_public_key.verify(signature_der, hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
        sigMsg = "Geldige Handtekening!"
        sigCheck = True
    except Exception as e:
        sigMsg = f"Ongeldige Handtekening! {e}"

    # --- Certificate Signature Validatie ---
    cert_signature = bytes(signer_cert['signature'])
    cert_tbs_der = encoder.encode(tbs_cert)
    try:
        cert_public_key.verify(cert_signature, cert_tbs_der, ec.ECDSA(hashes.SHA256()))
        certMsg = "Geldig Certificaat!"
        certCheck = True
    except Exception as e:
        certMsg = f"Ongeldig Certificaat! {e}"

# --- RAPPORT ---
terminal.logValidation(enc=encCheck, pskId=pskIdCheck, cert_time=certTimeCheck, time=timeCheck, sig=sigCheck, cert=certCheck)
terminal.logDetailedValidation(encMsg=encMsg, pskIdMsg=pskIdMsg, certTimeMsg=certTimeMsg, timeMsg=timeMsg, sigMsg=sigMsg, certMsg=certMsg)
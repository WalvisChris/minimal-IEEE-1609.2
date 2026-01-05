import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import os

KEY_DIR = "keys/"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public_key.pem")
PSK_KEY_FILE = os.path.join(KEY_DIR, "psk.txt")
CURVE = ec.SECP256R1()

# 1. Maak de map aan
os.system('cls')
os.makedirs(KEY_DIR, exist_ok=True)

# 2. Genereer de keys
private_key = ec.generate_private_key(CURVE)
public_key = private_key.public_key()

# 3. Private Key Opslaan
private_pem = private_key.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()
)
with open(PRIVATE_KEY_FILE, "wb") as f:
    f.write(private_pem)
print("private key aangemaakt")

# 4. Public Key Opslaan
public_pem = public_key.public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
)
with open(PUBLIC_KEY_FILE, "wb") as f:
    f.write(public_pem)
print("public key aangemaakt")

# 5. PSK
psk = os.urandom(16)
with open(PSK_KEY_FILE, "wb") as f:
    f.write(psk)
print("psk aangemaakt")

print("INFO: De nieuwe sleutels zijn beschikbaar via keys.private_key en keys.public_key.")
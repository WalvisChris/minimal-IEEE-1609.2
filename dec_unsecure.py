from pyasn1.codec.der import decoder
from lib.asn1.unsecureASN1 import *
from lib.TerminalInterface import *

# Paths
INPUT_PATH = "messages/msg_unsecure.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()

# Variables
with open(INPUT_PATH, "rb") as f:
    encoded_data = f.read()

decoded_data, _ = decoder.decode(encoded_data, asn1Spec=Ieee1609Dot2Data())

# === Print ===
_ = f"bericht opgehaald uit {INPUT_PATH}"
terminal.text(text=_)
terminal.printASN1(decoded_data)
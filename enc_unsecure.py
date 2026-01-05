from lib.TerminalInterface import *
from lib.asn1.unsecureASN1 import *
from pyasn1.codec.der import encoder

# Paths
OUTPUT_PATH = "messages/msg_unsecure.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
payload_bytes = payload.encode('utf-8')
terminal.clear()

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()
ieee_content['unsecureData'] = payload_bytes

# === Ieee1609Dot2Data ====
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
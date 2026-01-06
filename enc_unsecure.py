from pyasn1.codec.der import encoder
from lib.TerminalInterface import *
from lib.asn1.unsecureASN1 import *

# Paths
OUTPUT_PATH = "messages/msg_unsecure.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()

# Variables
payload_bytes = payload.encode('utf-8')

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = Ieee1609Dot2Content()
ieee_data['content']['unsecureData'] = payload_bytes

# Send
final_bytes = encoder.encode(ieee_data)
with open(OUTPUT_PATH, "wb") as f:
    f.write(final_bytes)

# Result
terminal.printASN1(ieee_data)
_ = f"bericht opgeslagen in {OUTPUT_PATH}"
terminal.text(text=_)
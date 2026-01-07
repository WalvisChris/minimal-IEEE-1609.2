from pyasn1.codec.der import encoder
from lib.TerminalInterface import *
from lib.asn1.unsecureASN1 import *

# Terminal & Timer
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()
terminal.startTimer()
times = []

# Paths
OUTPUT_PATH = "messages/msg_unsecure.txt"

# Variables
payload_bytes = payload.encode('utf-8')

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = Ieee1609Dot2Content()
ieee_data['content']['unsecureData'] = payload_bytes
times.append(("ASN.1 inpakken", terminal.getTimeStamp()))

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
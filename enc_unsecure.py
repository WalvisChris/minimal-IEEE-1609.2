from lib.TerminalInterface import *
from lib.minimalASN1 import *

# Paths
OUTPUT_PATH = "messages/msg_signed.txt"

# Terminal
terminal = TerminalInterface()
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.clear()

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()

# === Ieee1609Dot2Data ====
ieee_data = Ieee1609Dot2Data()

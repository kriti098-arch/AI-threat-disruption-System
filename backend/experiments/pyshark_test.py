"""
Proof-of-concept script to verify PyShark + tshark integration.
Not part of production pipeline.
"""

import pyshark

capture = pyshark.LiveCapture(interface="Wi-Fi")
packet = next(capture.sniff_continuously(packet_count=1))
print(packet)

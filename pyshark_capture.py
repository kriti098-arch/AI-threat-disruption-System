import pyshark
import requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000/network-events/"

def start_capture():
    print("🚀 Starting live packet capture → FastAPI\n")

    capture = pyshark.LiveCapture(interface="Wi-Fi")  # change if needed

    for packet in capture.sniff_continuously():
        try:
            data = {
                "src_ip": packet.ip.src,
                "dst_ip": packet.ip.dst,
                "protocol": packet.highest_layer,
                "packet_size": int(packet.length),
                "timestamp": datetime.now().isoformat()
            }

            response = requests.post(API_URL, json=data)

            print("📡 Sent:", data)
            print("🧠 API status:", response.status_code)

        except AttributeError:
            continue
        except Exception as e:
            print("❌ Error:", e)

if __name__ == "__main__":
    start_capture()

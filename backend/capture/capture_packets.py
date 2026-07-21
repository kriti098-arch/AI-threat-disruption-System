import pyshark
import requests

API_URL = "http://127.0.0.1:8000/network-events/"

def capture_packets():
    capture = pyshark.LiveCapture(interface="Wi-Fi")

    for packet in capture.sniff_continuously(packet_count=50):
        try:
            if hasattr(packet, "ip"):
                data = {
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "protocol": packet.transport_layer,
                    "packet_size": int(packet.length)
                }

                response = requests.post(API_URL, json=data)
                print("Sent:", data, "Status:", response.status_code)

        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    capture_packets()

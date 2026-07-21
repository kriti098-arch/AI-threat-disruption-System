from fastapi import APIRouter, WebSocket
from app.ml.stream_detector import StreamDetector
import time

router = APIRouter()
detector = StreamDetector()
@router.websocket("/ws/live-capture")
async def live_capture_socket(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_json()

            # Expected input from packet sniffer
            packet_size = data.get("packet_size", 0)
            src_ip = data.get("src_ip", "unknown")

            detector.add_event(packet_size, src_ip)
            ml_result = detector.detect()

            payload = {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "packet_size": packet_size,
                "anomaly": ml_result["anomaly"] if ml_result else False,
                "score": ml_result["score"] if ml_result else 0
            }

            await websocket.send_json(payload)

    except Exception:
        await websocket.close()

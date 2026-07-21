# app/features/extractor.py

def extract_features(events):
    """
    Extract statistical features from recent network events.
    events: List[NetworkEvent ORM objects]
    """

    # Packet sizes (ignore None)
    packet_sizes = [
        e.packet_size for e in events if e.packet_size is not None
    ]

    total_packets = len(packet_sizes)
    total_bytes = sum(packet_sizes)

    avg_packet_size = (
        total_bytes / total_packets if total_packets > 0 else 0
    )

    # Protocol distribution
    protocols = {}
    for e in events:
        if e.protocol:
            protocols[e.protocol] = protocols.get(e.protocol, 0) + 1

    features = {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "avg_packet_size": avg_packet_size,
        "protocol_distribution": protocols
    }

    return features

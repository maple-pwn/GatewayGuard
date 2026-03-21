from app.routers.traffic import _build_simulation_packets, _packet_attack_type


def _attack_count(packets: list) -> int:
    return sum(
        1 for packet in packets
        if _packet_attack_type(packet.payload_decoded, packet.metadata)
    )


def test_packet_attack_type_detects_payload_marker():
    assert _packet_attack_type({"attack": "dos"}, {"attack": True}) == "dos"


def test_packet_attack_type_detects_metadata_marker():
    assert _packet_attack_type({}, {"attack": True}) == "simulated_attack"


def test_dos_demo_surfaces_attack_packets_in_latest_rows():
    packets = _build_simulation_packets("dos", 200, 1000.0)
    latest = sorted(packets, key=lambda packet: packet.timestamp, reverse=True)[:50]
    assert _attack_count(latest) >= 20


def test_mixed_demo_surfaces_attack_packets_in_latest_rows():
    packets = _build_simulation_packets("mixed", 200, 1000.0)
    latest = sorted(packets, key=lambda packet: packet.timestamp, reverse=True)[:50]
    assert _attack_count(latest) >= 20

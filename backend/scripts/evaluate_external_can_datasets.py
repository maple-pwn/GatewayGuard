#!/usr/bin/env python3

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if TYPE_CHECKING:
    from app.models.packet import UnifiedPacket


@dataclass
class LabeledPacket:
    packet: "UnifiedPacket"
    is_attack: bool


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "attack", "anomaly", "malicious"}


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_jsonl(path: Path) -> List[dict]:
    rows: List[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def load_csv(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def detect_format(path: Path, forced: str) -> str:
    if forced != "auto":
        return forced
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    return "csv"


def row_to_packet(row: dict) -> LabeledPacket:
    from app.models.packet import UnifiedPacket

    label = (
        row.get("attack")
        if "attack" in row
        else row.get("is_attack", row.get("label", row.get("y", False)))
    )

    payload_decoded = row.get("payload_decoded", {})
    if isinstance(payload_decoded, str):
        payload_decoded = payload_decoded.strip()
        if payload_decoded:
            try:
                payload_decoded = json.loads(payload_decoded)
            except json.JSONDecodeError:
                payload_decoded = {}
        else:
            payload_decoded = {}

    metadata = row.get("metadata", {})
    if isinstance(metadata, str):
        metadata = metadata.strip()
        if metadata:
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}
        else:
            metadata = {}

    packet = UnifiedPacket(
        timestamp=safe_float(row.get("timestamp")),
        protocol=str(row.get("protocol", "CAN")),
        source=str(row.get("source", "")),
        destination=str(row.get("destination", "")),
        msg_id=str(row.get("msg_id", "")),
        payload_hex=str(row.get("payload_hex", "")),
        payload_decoded=payload_decoded if isinstance(payload_decoded, dict) else {},
        domain=str(row.get("domain", "")),
        metadata=metadata if isinstance(metadata, dict) else {},
    )
    return LabeledPacket(packet=packet, is_attack=parse_bool(label))


def load_dataset(path: Path, fmt: str) -> List[LabeledPacket]:
    rows = load_jsonl(path) if fmt == "jsonl" else load_csv(path)
    data = [row_to_packet(row) for row in rows]
    data.sort(key=lambda x: x.packet.timestamp)
    return data


def split_dataset(
    data: Sequence[LabeledPacket], train_ratio: float
) -> Tuple[List[LabeledPacket], List[LabeledPacket]]:
    split_idx = max(1, min(len(data) - 1, int(len(data) * train_ratio)))
    return list(data[:split_idx]), list(data[split_idx:])


def group_attack_events(
    samples: Sequence[LabeledPacket], max_gap_s: float = 0.2
) -> List[dict]:
    events: List[dict] = []
    current: Optional[dict] = None

    for item in samples:
        if not item.is_attack:
            current = None
            continue

        ts = item.packet.timestamp
        msg_id = item.packet.msg_id
        if current is None:
            current = {
                "first_seen": ts,
                "last_seen": ts,
                "packet_count": 1,
                "msg_ids": {msg_id},
            }
            events.append(current)
            continue

        same_cluster = (ts - current["last_seen"] <= max_gap_s) and (
            msg_id in current["msg_ids"]
        )
        if same_cluster:
            current["last_seen"] = ts
            current["packet_count"] += 1
            current["msg_ids"].add(msg_id)
        else:
            current = {
                "first_seen": ts,
                "last_seen": ts,
                "packet_count": 1,
                "msg_ids": {msg_id},
            }
            events.append(current)

    return events


def f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def binary_metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if tp + fp > 0 else 0.0
    recall = tp / (tp + fn) if tp + fn > 0 else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1(precision, recall),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def alert_key(packet: "UnifiedPacket") -> Tuple[int, str]:
    return (int(packet.timestamp * 1000), packet.msg_id)


def evaluate(detector: Any, test_data: Sequence[LabeledPacket]) -> dict:
    test_packets = [x.packet for x in test_data]
    alerts, events = detector.detect_with_aggregation(test_packets)

    gt_attack_keys = {alert_key(x.packet) for x in test_data if x.is_attack}
    predicted_keys = {
        (int(a.timestamp * 1000), a.target_node or a.source_node or "") for a in alerts
    }

    tp = len(predicted_keys & gt_attack_keys)
    fp = len(predicted_keys - gt_attack_keys)
    fn = len(gt_attack_keys - predicted_keys)
    packet_metrics = binary_metrics(tp, fp, fn)

    gt_events = group_attack_events(test_data)
    pred_events = [
        {
            "first_seen": e.first_seen,
            "last_seen": e.last_seen,
            "msg_ids": set(e.involved_ids),
        }
        for e in events
    ]

    matched_pred = set()
    matched_gt = set()
    for gi, gt in enumerate(gt_events):
        for pi, pred in enumerate(pred_events):
            if pi in matched_pred:
                continue
            overlap = not (
                pred["last_seen"] < gt["first_seen"]
                or pred["first_seen"] > gt["last_seen"]
            )
            shared_msg = bool(pred["msg_ids"] & gt["msg_ids"])
            if overlap and shared_msg:
                matched_gt.add(gi)
                matched_pred.add(pi)
                break

    event_tp = len(matched_gt)
    event_fp = len(pred_events) - event_tp
    event_fn = len(gt_events) - event_tp
    event_metrics = binary_metrics(event_tp, event_fp, event_fn)

    by_type = Counter(a.anomaly_type for a in alerts)
    by_method = Counter(a.detection_method for a in alerts)
    by_severity = Counter(a.severity for a in alerts)

    return {
        "packet_level": packet_metrics,
        "event_level": event_metrics,
        "detector_breakdown": {
            "by_anomaly_type": dict(by_type),
            "by_detection_method": dict(by_method),
            "by_severity": dict(by_severity),
        },
        "counts": {
            "test_packets": len(test_data),
            "ground_truth_attack_packets": len(gt_attack_keys),
            "predicted_alerts": len(alerts),
            "ground_truth_attack_events": len(gt_events),
            "predicted_events": len(events),
        },
    }


def main() -> int:
    from app.services.anomaly_detector import AnomalyDetectorService

    parser = argparse.ArgumentParser(
        description="Evaluate external CAN datasets with GatewayGuard profile-first detector"
    )
    parser.add_argument(
        "--input", required=True, help="Path to dataset file (csv/jsonl)"
    )
    parser.add_argument("--format", choices=["auto", "csv", "jsonl"], default="auto")
    parser.add_argument("--train-ratio", type=float, default=0.6)
    parser.add_argument("--output", help="Optional output JSON path")
    args = parser.parse_args()

    if not (0.1 <= args.train_ratio <= 0.9):
        raise ValueError("--train-ratio must be in [0.1, 0.9]")

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input dataset not found: {input_path}")

    fmt = detect_format(input_path, args.format)
    data = load_dataset(input_path, fmt)
    if len(data) < 20:
        raise ValueError("Dataset too small: need at least 20 rows")

    train_data, test_data = split_dataset(data, args.train_ratio)
    train_normal = [x.packet for x in train_data if not x.is_attack]
    if len(train_normal) < 10:
        raise ValueError("Insufficient benign packets in training split")

    detector = AnomalyDetectorService()
    detector.train(train_normal)
    if not detector.is_trained:
        raise RuntimeError(
            "Detector training failed; check train split quality and config"
        )

    result = {
        "input": str(input_path),
        "format": fmt,
        "train_ratio": args.train_ratio,
        "train_packets": len(train_data),
        "test_packets": len(test_data),
        "metrics": evaluate(detector, test_data),
    }

    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

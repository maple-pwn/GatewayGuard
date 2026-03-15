"""Evaluate GatewayGuard against public CAN intrusion datasets.

This script keeps the evaluation close to the current project behavior:
- it reuses the repository's `AnomalyDetectorService`
- it trains the detector on a normal-only window
- it evaluates stock alerts plus ML-like alerts on fixed windows

Supported dataset layouts:
- B-CAN / M-CAN CSV files from HCILab
- Car-Hacking dataset ZIP from HCRL/HCILab
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Deque, Dict, Iterator, Optional, Set, Tuple, Union


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.models.packet import UnifiedPacket
from app.services.anomaly_detector import AnomalyDetectorService


ML_METHOD_HINTS = ("iforest", "isolation_forest", "ml_")


NORMAL_LINE_RE = re.compile(
    r"Timestamp:\s*(?P<timestamp>\d+\.\d+)\s+"
    r"ID:\s*(?P<msg_id>[0-9A-Fa-f]+)\s+\d+\s+"
    r"DLC:\s*(?P<dlc>\d+)\s+"
    r"(?P<payload>(?:[0-9A-Fa-f]{2}(?:\s+|$))*)"
)
RA8P1_JSON_PREFIX_RE = re.compile(
    r'\{"seq":(?P<seq>\d+),"timestamp_u(?:s)?":(?P<timestamp_us>\d+),'
    r'"dataset":"(?P<dataset>[^"]+)","case":"(?P<case>[^"]+)",'
    r'"label":(?P<label>\d+),"attack_kind":"(?P<attack_kind>[^"]+)",'
    r'"can_id":"(?P<can_id>0x[0-9A-Fa-f]+)","dl'
)


@dataclass
class LabeledPacket:
    packet: UnifiedPacket
    label: int


@dataclass
class DatasetProfile:
    name: str
    train_factory: Callable[[], Iterator[LabeledPacket]]
    normal_eval_factory: Callable[[], Iterator[LabeledPacket]]
    attack_factories: Dict[str, Callable[[], Iterator[LabeledPacket]]]


def normalize_can_id(raw_id: str) -> str:
    raw_id = raw_id.strip().replace("0x", "").replace("0X", "")
    try:
        return f"0x{int(raw_id, 16):03X}"
    except ValueError:
        return f"0x{raw_id.upper()}"


def normalize_payload(parts: List[str], dlc: Optional[int] = None) -> str:
    values = [part.strip().replace("0x", "").replace("0X", "") for part in parts if part.strip()]
    if dlc is not None:
        values = values[:dlc]
    return "".join(value.zfill(2).upper() for value in values)


def normalize_payload_hex_string(raw_payload: str, dlc: Optional[int] = None) -> str:
    value = re.sub(r"[^0-9A-Fa-f]", "", raw_payload or "").upper()
    if dlc is not None:
        value = value[: dlc * 2]
    return value


def sanitize_csv_row(row: Dict[str, str]) -> Dict[str, str]:
    return {
        key.replace("\ufeff", "").strip().strip('"'): value
        for key, value in row.items()
        if key is not None
    }


def build_packet(timestamp: float, msg_id: str, payload_hex: str, label: int) -> UnifiedPacket:
    return UnifiedPacket(
        timestamp=timestamp,
        protocol="CAN",
        source="DATASET",
        destination="BROADCAST",
        msg_id=msg_id,
        payload_hex=payload_hex,
        payload_decoded={"dlc": len(payload_hex) // 2, "raw": payload_hex},
        domain="unknown",
        metadata={"attack": bool(label), "external_dataset": True},
    )


def iter_bmcan_csv(path: Path) -> Iterator[LabeledPacket]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            timestamp = float(row["Timestamp"])
            msg_id = normalize_can_id(row["ID"])
            payload_hex = normalize_payload(row["Payload"].split())
            label = int(float(row["label"]))
            yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, label), label)


def iter_ra8p1_csv(path: Path, normal_only: bool = False) -> Iterator[LabeledPacket]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for raw_row in reader:
            row = sanitize_csv_row(raw_row)
            label = int(row["label"])
            if normal_only and label != 0:
                continue

            timestamp = int(row["timestamp_us"]) / 1_000_000.0
            msg_id = normalize_can_id(row["can_id"])
            dlc = int(row["dlc"])
            payload_hex = normalize_payload_hex_string(row["data_hex"], dlc)
            yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, label), label)


def load_ra8p1_csv_index(path: Path) -> Dict[int, Dict[str, Union[int, str]]]:
    index: Dict[int, Dict[str, Union[int, str]]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for raw_row in reader:
            row = sanitize_csv_row(raw_row)
            seq = int(row["seq"])
            index[seq] = {
                "label": int(row["label"]),
                "timestamp_us": int(row["timestamp_us"]),
                "msg_id": normalize_can_id(row["can_id"]),
                "dlc": int(row["dlc"]),
                "payload_hex": normalize_payload_hex_string(row["data_hex"], int(row["dlc"])),
            }
    return index


def iter_ra8p1_jsonl_with_csv(
    jsonl_path: Path,
    csv_path: Path,
    normal_only: bool = False,
) -> Iterator[LabeledPacket]:
    csv_index = load_ra8p1_csv_index(csv_path)
    text = jsonl_path.read_text(encoding="utf-8", errors="ignore")
    seen_seq: Set[int] = set()

    for match in RA8P1_JSON_PREFIX_RE.finditer(text):
        seq = int(match.group("seq"))
        if seq in seen_seq:
            continue
        seen_seq.add(seq)

        csv_row = csv_index.get(seq)
        if csv_row is None:
            continue

        label = int(match.group("label"))
        if normal_only and label != 0:
            continue

        timestamp = int(match.group("timestamp_us")) / 1_000_000.0
        msg_id = normalize_can_id(match.group("can_id"))
        if msg_id != csv_row["msg_id"]:
            continue

        payload_hex = str(csv_row["payload_hex"])
        yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, label), label)


def iter_car_hacking_attack(zip_path: Path, member: str) -> Iterator[LabeledPacket]:
    with zipfile.ZipFile(zip_path) as archive, archive.open(member) as handle:
        for raw_line in handle:
            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 4:
                continue

            timestamp = float(parts[0])
            msg_id = normalize_can_id(parts[1])
            dlc = int(parts[2])
            payload_hex = normalize_payload(parts[3:-1], dlc)
            label = 1 if parts[-1] == "T" else 0
            yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, label), label)


def iter_car_hacking_normal(zip_path: Path, member: str) -> Iterator[LabeledPacket]:
    with zipfile.ZipFile(zip_path) as archive, archive.open(member) as handle:
        for raw_line in handle:
            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            match = NORMAL_LINE_RE.match(line)
            if not match:
                continue
            timestamp = float(match.group("timestamp"))
            msg_id = normalize_can_id(match.group("msg_id"))
            dlc = int(match.group("dlc"))
            payload_hex = normalize_payload(match.group("payload").split(), dlc)
            yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, 0), 0)


def iter_canfd_csv(
    zip_path: Path,
    member: str,
    normal_only: bool = False,
) -> Iterator[LabeledPacket]:
    with zipfile.ZipFile(zip_path) as archive, archive.open(member) as handle:
        reader = csv.reader((line.decode("utf-8", errors="ignore") for line in handle))
        for row in reader:
            if len(row) < 4:
                continue

            timestamp = float(row[0].strip())
            msg_id = normalize_can_id(row[1])
            dlc = int(row[2].strip())
            payload_hex = normalize_payload(row[3:-1], dlc)
            label = 1 if row[-1].strip().upper() == "T" else 0

            if normal_only and label != 0:
                continue

            yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, label), label)


def iter_canfd_normal_all(zip_path: Path) -> Iterator[LabeledPacket]:
    members = [
        "CAN-FD_Intrusion_Dataset/CANFD_Flooding.csv",
        "CAN-FD_Intrusion_Dataset/CANFD_Fuzzing.csv",
        "CAN-FD_Intrusion_Dataset/CANFD_Malfunction.csv",
    ]
    for member in members:
        yield from iter_canfd_csv(zip_path, member, normal_only=True)


def _read_otids_inner_zip(outer_zip_path: Path, inner_name: str) -> zipfile.ZipFile:
    outer = zipfile.ZipFile(outer_zip_path)
    data = outer.read(inner_name)
    outer.close()
    return zipfile.ZipFile(io.BytesIO(data))


def load_otids_windows(
    outer_zip_path: Path,
    inner_name: str,
) -> List[Tuple[float, float, str]]:
    with _read_otids_inner_zip(outer_zip_path, inner_name) as inner:
        csv_name = next(name for name in inner.namelist() if name.lower().endswith(".csv"))
        raw = inner.read(csv_name).decode("utf-8", errors="ignore").splitlines()

    windows: List[Tuple[float, float, str]] = []
    for line in raw:
        line = line.strip().replace("\ufeff", "").replace("\ufffd", "")
        if not line:
            continue
        parts = [part.strip() for part in line.split(",") if part.strip()]
        if len(parts) < 3:
            continue
        try:
            start = float(parts[0])
            end = float(parts[1])
            attack_type = parts[2]
        except ValueError:
            continue
        windows.append((start, end, attack_type))
    windows.sort(key=lambda item: item[0])
    return windows


def iter_otids_packets(
    outer_zip_path: Path,
    inner_name: str,
    normal_only: bool = False,
    attack_type_filter: Optional[str] = None,
    segment_start: Optional[float] = None,
    segment_end: Optional[float] = None,
) -> Iterator[LabeledPacket]:
    windows = load_otids_windows(outer_zip_path, inner_name)
    all_windows = [(start, end) for start, end, _ in windows]
    if attack_type_filter:
        attack_windows = [(start, end) for start, end, attack_type in windows if attack_type == attack_type_filter]
    else:
        attack_windows = all_windows

    def _in_windows(timestamp: float, intervals: List[Tuple[float, float]]) -> bool:
        return any(start <= timestamp <= end for start, end in intervals)

    with _read_otids_inner_zip(outer_zip_path, inner_name) as inner:
        txt_name = next(name for name in inner.namelist() if name.lower().endswith(".txt"))
        with inner.open(txt_name) as handle:
            for raw_line in handle:
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                match = NORMAL_LINE_RE.match(line)
                if not match:
                    continue

                timestamp = float(match.group("timestamp"))
                if segment_start is not None and timestamp < segment_start:
                    continue
                if segment_end is not None and timestamp > segment_end:
                    continue

                in_any_attack = _in_windows(timestamp, all_windows)
                in_target_attack = _in_windows(timestamp, attack_windows)

                if normal_only and in_any_attack:
                    continue

                label = 1 if in_target_attack else 0
                msg_id = normalize_can_id(match.group("msg_id"))
                dlc = int(match.group("dlc"))
                payload_hex = normalize_payload(match.group("payload").split(), dlc)
                yield LabeledPacket(build_packet(timestamp, msg_id, payload_hex, label), label)


def make_otids_attack_segment_factory(
    outer_zip_path: Path,
    inner_name: str,
    attack_type: str,
    pre_seconds: float = 2.0,
    post_seconds: float = 2.0,
) -> Callable[[], Iterator[LabeledPacket]]:
    windows = load_otids_windows(outer_zip_path, inner_name)
    target = next((item for item in windows if item[2] == attack_type), None)
    if target is None:
        return lambda: iter(())
    start, end, _ = target
    return lambda: iter_otids_packets(
        outer_zip_path=outer_zip_path,
        inner_name=inner_name,
        attack_type_filter=attack_type,
        segment_start=start - pre_seconds,
        segment_end=end + post_seconds,
    )


def take_first(factory: Callable[[], Iterator[LabeledPacket]], limit: int) -> List[LabeledPacket]:
    result: List[LabeledPacket] = []
    for index, sample in enumerate(factory()):
        if index >= limit:
            break
        result.append(sample)
    return result


def skip_and_take(
    factory: Callable[[], Iterator[LabeledPacket]],
    skip: int,
    limit: int,
) -> List[LabeledPacket]:
    result: List[LabeledPacket] = []
    for index, sample in enumerate(factory()):
        if index < skip:
            continue
        if len(result) >= limit:
            break
        result.append(sample)
    return result


def take_last(factory: Callable[[], Iterator[LabeledPacket]], limit: int) -> List[LabeledPacket]:
    result: Deque[LabeledPacket] = deque(maxlen=limit)
    for sample in factory():
        result.append(sample)
    return list(result)


def take_attack_window(
    factory: Callable[[], Iterator[LabeledPacket]],
    limit: int,
    pre_attack_rows: Optional[int] = None,
) -> List[LabeledPacket]:
    if pre_attack_rows is None:
        pre_attack_rows = max(1, limit // 5)

    prefix: Deque[LabeledPacket] = deque(maxlen=pre_attack_rows)
    window: List[LabeledPacket] = []
    attack_started = False

    for sample in factory():
        if not attack_started:
            prefix.append(sample)
            if sample.label == 1:
                attack_started = True
                window.extend(prefix)
        else:
            window.append(sample)
            if len(window) >= limit:
                break

    if attack_started:
        return window[:limit]
    return take_last(factory, limit)


def compute_ml_metrics(
    packets: List[UnifiedPacket],
    labels: List[int],
    ml_alert_timestamps: List[float],
) -> Dict[str, Union[Optional[float], int]]:
    predicted = [0] * len(packets)
    ts_to_indices: Dict[float, Deque[int]] = defaultdict(deque)
    for index, packet in enumerate(packets):
        ts_to_indices[packet.timestamp].append(index)

    for timestamp in ml_alert_timestamps:
        if ts_to_indices[timestamp]:
            predicted[ts_to_indices[timestamp].popleft()] = 1

    tp = sum(1 for label, pred in zip(labels, predicted) if label == 1 and pred == 1)
    fp = sum(1 for label, pred in zip(labels, predicted) if label == 0 and pred == 1)
    tn = sum(1 for label, pred in zip(labels, predicted) if label == 0 and pred == 0)
    fn = sum(1 for label, pred in zip(labels, predicted) if label == 1 and pred == 0)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall)
        else None
    )
    fpr = fp / (fp + tn) if (fp + tn) else None

    return {
        "predicted_positive": sum(predicted),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "false_positive_rate": round(fpr, 4) if fpr is not None else None,
    }


def _is_ml_alert(alert) -> bool:
    method = (getattr(alert, "detection_method", "") or "").lower()
    anomaly_type = (getattr(alert, "anomaly_type", "") or "").lower()
    return any(hint in method for hint in ML_METHOD_HINTS) or anomaly_type.startswith(
        "ml_"
    )


def collect_alerts(
    detector: AnomalyDetectorService,
    packets: List[UnifiedPacket],
) -> Tuple[list, list, list]:
    if hasattr(detector, "rule_detector") and hasattr(detector, "ml_detector"):
        rule_alerts = list(detector.rule_detector.check(packets))
        ml_alerts = list(detector.ml_detector.predict(packets))
        alerts = sorted(
            rule_alerts + ml_alerts,
            key=lambda alert: alert.confidence,
            reverse=True,
        )
        return alerts, rule_alerts, ml_alerts

    alerts = list(detector.detect(packets))
    alerts.sort(key=lambda alert: alert.confidence, reverse=True)
    ml_alerts = [alert for alert in alerts if _is_ml_alert(alert)]
    rule_alerts = [alert for alert in alerts if not _is_ml_alert(alert)]
    return alerts, rule_alerts, ml_alerts


def get_known_id_metrics(
    detector: AnomalyDetectorService,
    unique_ids: Set[str],
) -> Tuple[Optional[int], Optional[int]]:
    builtin_hits: Optional[int] = None
    trained_profile_hits: Optional[int] = None

    if hasattr(detector, "rule_detector") and hasattr(
        detector.rule_detector, "VALID_CAN_IDS"
    ):
        builtin_hits = len(unique_ids & set(detector.rule_detector.VALID_CAN_IDS))
        learned_ids = getattr(detector.rule_detector, "learned_can_ids", set())
        if learned_ids:
            trained_profile_hits = len(unique_ids & set(learned_ids))
    elif hasattr(detector, "profile_mgr") and hasattr(
        detector.profile_mgr, "get_all_known_ids"
    ):
        known_ids = set(detector.profile_mgr.get_all_known_ids())
        trained_profile_hits = len(unique_ids & known_ids)

    return builtin_hits, trained_profile_hits


def summarize_case(
    detector: AnomalyDetectorService,
    dataset_name: str,
    case_name: str,
    labeled_packets: List[LabeledPacket],
) -> Dict[str, object]:
    packets = [sample.packet for sample in labeled_packets]
    labels = [sample.label for sample in labeled_packets]

    alerts, rule_alerts, ml_alerts = collect_alerts(detector, packets)

    alert_methods = Counter(alert.detection_method for alert in alerts)
    alert_types = Counter(alert.anomaly_type for alert in alerts)
    unique_ids = {packet.msg_id for packet in packets}
    builtin_hits, trained_profile_hits = get_known_id_metrics(detector, unique_ids)

    ml_metrics = compute_ml_metrics(
        packets=packets,
        labels=labels,
        ml_alert_timestamps=[alert.timestamp for alert in ml_alerts],
    )

    return {
        "dataset": dataset_name,
        "case": case_name,
        "rows": len(packets),
        "attack_rows": int(sum(labels)),
        "attack_ratio": round(sum(labels) / len(labels), 4) if labels else 0.0,
        "unique_ids": len(unique_ids),
        "unique_ids_in_builtin_whitelist": builtin_hits,
        "unique_ids_in_trained_profile": trained_profile_hits,
        "stock_alerts_total": len(alerts),
        "stock_rule_alerts": len(rule_alerts),
        "stock_ml_alerts": len(ml_alerts),
        "alert_types": dict(alert_types),
        "alert_methods": dict(alert_methods),
        "sample_alerts": [
            {
                "type": alert.anomaly_type,
                "method": alert.detection_method,
                "severity": alert.severity,
                "description": alert.description,
            }
            for alert in alerts[:5]
        ],
        "ml_packet_metrics": ml_metrics,
    }


def find_datasets_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "datasets"
        if candidate.exists():
            return candidate
    return Path.cwd() / "datasets"


def find_optional_local_file(filename: str) -> Optional[Path]:
    candidates = [PROJECT_ROOT, *PROJECT_ROOT.parents, Path.cwd()]
    seen: Set[Path] = set()
    for root in candidates:
        candidate = root / filename
        try:
            resolved = candidate.resolve()
        except FileNotFoundError:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        if candidate.exists():
            return candidate
    return None


def build_profiles(
    datasets_root: Path,
    ra8p1_jsonl_path: Optional[Path] = None,
    ra8p1_csv_path: Optional[Path] = None,
) -> List[DatasetProfile]:
    bcan_dir = datasets_root / "extracted" / "bcan"
    mcan_dir = datasets_root / "extracted" / "mcan" / "inner"
    car_zip = datasets_root / "downloads" / "car-hacking.zip"
    canfd_zip = datasets_root / "downloads" / "canfd.zip"
    otids_zip = datasets_root / "downloads" / "otids.zip"

    profiles: List[DatasetProfile] = []

    if (bcan_dir / "g80_bcan_normal_data.csv").exists():
        profiles.append(
            DatasetProfile(
                name="B-CAN",
                train_factory=lambda: iter_bmcan_csv(bcan_dir / "g80_bcan_normal_data.csv"),
                normal_eval_factory=lambda: iter_bmcan_csv(bcan_dir / "g80_bcan_normal_data.csv"),
                attack_factories={
                    "ddos_tail": lambda: iter_bmcan_csv(bcan_dir / "g80_bcan_ddos_data.csv"),
                    "fuzzing_tail": lambda: iter_bmcan_csv(bcan_dir / "g80_bcan_fuzzing_data.csv"),
                },
            )
        )

    if (mcan_dir / "g80_mcan_normal_data.csv").exists():
        profiles.append(
            DatasetProfile(
                name="M-CAN",
                train_factory=lambda: iter_bmcan_csv(mcan_dir / "g80_mcan_normal_data.csv"),
                normal_eval_factory=lambda: iter_bmcan_csv(mcan_dir / "g80_mcan_normal_data.csv"),
                attack_factories={
                    "ddos_tail": lambda: iter_bmcan_csv(mcan_dir / "g80_mcan_ddos_data.csv"),
                    "fuzzing_tail": lambda: iter_bmcan_csv(mcan_dir / "g80_mcan_fuzzing_data.csv"),
                },
            )
        )

    if car_zip.exists():
        profiles.append(
            DatasetProfile(
                name="Car-Hacking",
                train_factory=lambda: iter_car_hacking_normal(
                    car_zip, "normal_run_data/normal_run_data.txt"
                ),
                normal_eval_factory=lambda: iter_car_hacking_normal(
                    car_zip, "normal_run_data/normal_run_data.txt"
                ),
                attack_factories={
                    "dos_tail": lambda: iter_car_hacking_attack(car_zip, "DoS_dataset.csv"),
                    "fuzzy_tail": lambda: iter_car_hacking_attack(car_zip, "Fuzzy_dataset.csv"),
                    "rpm_tail": lambda: iter_car_hacking_attack(car_zip, "RPM_dataset.csv"),
                    "gear_tail": lambda: iter_car_hacking_attack(car_zip, "gear_dataset.csv"),
                },
            )
        )

    if canfd_zip.exists():
        profiles.append(
            DatasetProfile(
                name="CAN-FD",
                train_factory=lambda: iter_canfd_normal_all(canfd_zip),
                normal_eval_factory=lambda: iter_canfd_normal_all(canfd_zip),
                attack_factories={
                    "flooding": lambda: iter_canfd_csv(
                        canfd_zip, "CAN-FD_Intrusion_Dataset/CANFD_Flooding.csv"
                    ),
                    "fuzzing": lambda: iter_canfd_csv(
                        canfd_zip, "CAN-FD_Intrusion_Dataset/CANFD_Fuzzing.csv"
                    ),
                    "malfunction": lambda: iter_canfd_csv(
                        canfd_zip, "CAN-FD_Intrusion_Dataset/CANFD_Malfunction.csv"
                    ),
                },
            )
        )

    if otids_zip.exists():
        otids_inner = "KU-CISC2017-OTIDS-2nd.zip"
        profiles.append(
            DatasetProfile(
                name="OTIDS-2nd",
                train_factory=lambda: iter_otids_packets(
                    outer_zip_path=otids_zip,
                    inner_name=otids_inner,
                    normal_only=True,
                ),
                normal_eval_factory=lambda: iter_otids_packets(
                    outer_zip_path=otids_zip,
                    inner_name=otids_inner,
                    normal_only=True,
                ),
                attack_factories={
                    "dos_segment": make_otids_attack_segment_factory(otids_zip, otids_inner, "DoS"),
                    "fuzzy_segment": make_otids_attack_segment_factory(otids_zip, otids_inner, "Fuzzy"),
                    "replay_segment": make_otids_attack_segment_factory(otids_zip, otids_inner, "Replay"),
                },
            )
        )

    if ra8p1_csv_path and ra8p1_csv_path.exists():
        profiles.append(
            DatasetProfile(
                name="RA8P1-CSV",
                train_factory=lambda: iter_ra8p1_csv(ra8p1_csv_path, normal_only=True),
                normal_eval_factory=lambda: iter_ra8p1_csv(ra8p1_csv_path, normal_only=True),
                attack_factories={
                    "ddos_tail": lambda: iter_ra8p1_csv(ra8p1_csv_path, normal_only=False),
                },
            )
        )

    if (
        ra8p1_jsonl_path
        and ra8p1_jsonl_path.exists()
        and ra8p1_csv_path
        and ra8p1_csv_path.exists()
    ):
        profiles.append(
            DatasetProfile(
                name="RA8P1-JSONL+CSV",
                train_factory=lambda: iter_ra8p1_jsonl_with_csv(
                    ra8p1_jsonl_path, ra8p1_csv_path, normal_only=True
                ),
                normal_eval_factory=lambda: iter_ra8p1_jsonl_with_csv(
                    ra8p1_jsonl_path, ra8p1_csv_path, normal_only=True
                ),
                attack_factories={
                    "ddos_tail": lambda: iter_ra8p1_jsonl_with_csv(
                        ra8p1_jsonl_path, ra8p1_csv_path, normal_only=False
                    ),
                },
            )
        )

    return profiles


def run_evaluation(
    profiles: List[DatasetProfile],
    train_rows: int,
    eval_rows: int,
) -> List[dict]:
    results: List[dict] = []

    for profile in profiles:
        train_samples = take_first(profile.train_factory, train_rows)
        if not train_samples:
            continue

        detector = AnomalyDetectorService()
        detector.train([sample.packet for sample in train_samples])

        normal_eval_samples = skip_and_take(profile.normal_eval_factory, train_rows, eval_rows)
        if not normal_eval_samples:
            fallback_rows = min(eval_rows, max(1, len(train_samples)))
            normal_eval_samples = take_last(profile.normal_eval_factory, fallback_rows)
        if normal_eval_samples:
            results.append(
                summarize_case(
                    detector=detector,
                    dataset_name=profile.name,
                    case_name="normal_eval",
                    labeled_packets=normal_eval_samples,
                )
            )

        for case_name, factory in profile.attack_factories.items():
            attack_eval_samples = take_attack_window(factory, eval_rows)
            if not attack_eval_samples:
                continue
            results.append(
                summarize_case(
                    detector=detector,
                    dataset_name=profile.name,
                    case_name=case_name,
                    labeled_packets=attack_eval_samples,
                )
            )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--datasets-root",
        type=Path,
        default=find_datasets_root(),
        help="Root directory containing downloaded/extracted public datasets.",
    )
    parser.add_argument(
        "--train-rows",
        type=int,
        default=100_000,
        help="Number of normal rows used to train Isolation Forest.",
    )
    parser.add_argument(
        "--eval-rows",
        type=int,
        default=100_000,
        help="Window size used for normal/attack evaluation.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=PROJECT_ROOT / "reports" / "external_can_eval.json",
        help="Where to save the JSON summary.",
    )
    parser.add_argument(
        "--ra8p1-jsonl",
        type=Path,
        default=find_optional_local_file("ra8p1_flow_20260312_232920.jsonl"),
        help="Optional local RA8P1 JSONL export to evaluate.",
    )
    parser.add_argument(
        "--ra8p1-csv",
        type=Path,
        default=find_optional_local_file("ra8p1_flow_20260312_232920_partial.csv"),
        help="Optional local RA8P1 CSV export to evaluate.",
    )
    parser.add_argument(
        "--enable-iforest-aux",
        action="store_true",
        help="Enable the current repo's auxiliary Isolation Forest branch during evaluation.",
    )
    args = parser.parse_args()

    settings.detector.enable_iforest_aux = bool(args.enable_iforest_aux)

    profiles = build_profiles(
        args.datasets_root,
        ra8p1_jsonl_path=args.ra8p1_jsonl,
        ra8p1_csv_path=args.ra8p1_csv,
    )
    if not profiles:
        print("No supported datasets found under", args.datasets_root)
        return 1

    results = run_evaluation(
        profiles=profiles,
        train_rows=args.train_rows,
        eval_rows=args.eval_rows,
    )

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(
            {
                "datasets_root": str(args.datasets_root),
                "ra8p1_jsonl": str(args.ra8p1_jsonl) if args.ra8p1_jsonl else None,
                "ra8p1_csv": str(args.ra8p1_csv) if args.ra8p1_csv else None,
                "train_rows": args.train_rows,
                "eval_rows": args.eval_rows,
                "enable_iforest_aux": bool(settings.detector.enable_iforest_aux),
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"Wrote {len(results)} case summaries to {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

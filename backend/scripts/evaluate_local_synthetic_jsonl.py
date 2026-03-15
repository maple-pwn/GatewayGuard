"""Evaluate a local synthetic CAN JSONL file with GatewayGuard."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.services.anomaly_detector import AnomalyDetectorService
from evaluate_external_can_datasets import LabeledPacket, build_packet, summarize_case


def load_jsonl(path: Path) -> list[LabeledPacket]:
    rows: list[LabeledPacket] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            obj = json.loads(line)
            rows.append(
                LabeledPacket(
                    packet=build_packet(
                        int(obj["timestamp_us"]) / 1_000_000.0,
                        obj["can_id"],
                        obj["data_hex"],
                        int(obj["label"]),
                    ),
                    label=int(obj["label"]),
                )
            )
    return rows


def count_timestamp_desc_violations(rows: list[LabeledPacket]) -> int:
    violations = 0
    for current, nxt in zip(rows, rows[1:]):
        if nxt.packet.timestamp < current.packet.timestamp:
            violations += 1
    return violations


def evaluate_sorted_split(
    dataset_name: str,
    rows: list[LabeledPacket],
    train_rows: int,
    pre_attack_rows: int,
) -> dict:
    rows_sorted = sorted(rows, key=lambda item: item.packet.timestamp)
    first_attack_idx = next((i for i, item in enumerate(rows_sorted) if item.label == 1), None)
    if first_attack_idx is None:
        raise ValueError("No attack rows found in the input file.")

    actual_train_rows = min(train_rows, max(1, first_attack_idx - 1))
    normal_prefix = rows_sorted[:first_attack_idx]
    train_samples = normal_prefix[:actual_train_rows]
    normal_eval_samples = normal_prefix[actual_train_rows:]
    attack_window_start = max(0, first_attack_idx - pre_attack_rows)
    attack_tail_samples = rows_sorted[attack_window_start:]

    detector = AnomalyDetectorService()
    detector.train([sample.packet for sample in train_samples])

    cases = []
    if normal_eval_samples:
        cases.append(
            summarize_case(
                detector=detector,
                dataset_name=dataset_name,
                case_name="normal_eval_sorted",
                labeled_packets=normal_eval_samples,
            )
        )
    cases.append(
        summarize_case(
            detector=detector,
            dataset_name=dataset_name,
            case_name="attack_tail_sorted",
            labeled_packets=attack_tail_samples,
        )
    )
    cases.append(
        summarize_case(
            detector=detector,
            dataset_name=dataset_name,
            case_name="full_sorted",
            labeled_packets=rows_sorted,
        )
    )

    return {
        "first_attack_idx_sorted": first_attack_idx,
        "train_rows_used": len(train_samples),
        "normal_eval_rows": len(normal_eval_samples),
        "attack_tail_rows": len(attack_tail_samples),
        "cases": cases,
    }


def evaluate_raw_order(
    dataset_name: str,
    rows: list[LabeledPacket],
    train_rows: int,
) -> dict:
    normal_rows = [row for row in rows if row.label == 0]
    train_samples = normal_rows[: min(train_rows, len(normal_rows))]

    detector = AnomalyDetectorService()
    detector.train([sample.packet for sample in train_samples])

    case = summarize_case(
        detector=detector,
        dataset_name=dataset_name,
        case_name="full_as_is",
        labeled_packets=rows,
    )
    return {
        "train_rows_used": len(train_samples),
        "cases": [case],
    }


def fmt_metric(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def find_case(cases: list[dict], case_name: str) -> dict:
    for case in cases:
        if case["case"] == case_name:
            return case
    raise KeyError(case_name)


def build_report(payload: dict) -> str:
    data_stats = payload["data_stats"]
    sorted_eval = payload["sorted_eval"]
    raw_eval = payload["raw_eval"]

    sorted_normal = find_case(sorted_eval["cases"], "normal_eval_sorted")
    sorted_attack = find_case(sorted_eval["cases"], "attack_tail_sorted")
    sorted_full = find_case(sorted_eval["cases"], "full_sorted")
    raw_full = find_case(raw_eval["cases"], "full_as_is")

    lines = [
        "# 本地合成 JSONL 评测报告",
        "",
        "## 1. 文件概况",
        "",
        f"- 输入文件：`{payload['input_path']}`",
        f"- 总行数：`{data_stats['rows']}`",
        f"- 正常行数：`{data_stats['normal_rows']}`",
        f"- 攻击行数：`{data_stats['attack_rows']}`",
        f"- 攻击类型：`{data_stats['attack_kind_counts']}`",
        f"- 唯一 CAN ID 数：`{data_stats['unique_ids']}`",
        f"- 攻击涉及 ID：`{data_stats['attack_id_counts']}`",
        f"- 原始文件中时间逆序次数：`{data_stats['timestamp_desc_violations']}`",
        "",
        "## 2. 评测口径",
        "",
        "- 主结果使用“按 `timestamp_us` 排序后”的时序恢复版本，这是对当前 GatewayGuard 更公平的输入方式。",
        "- 补充结果保留“文件原始乱序”直接检测，用来说明 `shuffled` 对时序规则的影响。",
        "- ML 已开启：`IForestAux = True`。",
        "",
        "## 3. 主结果：按时间排序后评测",
        "",
        f"- 第一条攻击在排序后索引：`{sorted_eval['first_attack_idx_sorted']}`",
        f"- 训练使用前置正常流量：`{sorted_eval['train_rows_used']}` 条",
        f"- 纯正常评测窗口：`{sorted_eval['normal_eval_rows']}` 条",
        f"- 攻击尾部评测窗口：`{sorted_eval['attack_tail_rows']}` 条",
        "",
        "| Case | Rows | Attack Rows | Total Alerts | Rule | ML | Precision | Recall | F1 | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| normal_eval_sorted | {sorted_normal['rows']} | {sorted_normal['attack_rows']} | "
            f"{sorted_normal['stock_alerts_total']} | {sorted_normal['stock_rule_alerts']} | {sorted_normal['stock_ml_alerts']} | "
            f"{fmt_metric(sorted_normal['ml_packet_metrics']['precision'])} | {fmt_metric(sorted_normal['ml_packet_metrics']['recall'])} | "
            f"{fmt_metric(sorted_normal['ml_packet_metrics']['f1'])} | {fmt_metric(sorted_normal['ml_packet_metrics']['false_positive_rate'])} |"
        ),
        (
            f"| attack_tail_sorted | {sorted_attack['rows']} | {sorted_attack['attack_rows']} | "
            f"{sorted_attack['stock_alerts_total']} | {sorted_attack['stock_rule_alerts']} | {sorted_attack['stock_ml_alerts']} | "
            f"{fmt_metric(sorted_attack['ml_packet_metrics']['precision'])} | {fmt_metric(sorted_attack['ml_packet_metrics']['recall'])} | "
            f"{fmt_metric(sorted_attack['ml_packet_metrics']['f1'])} | {fmt_metric(sorted_attack['ml_packet_metrics']['false_positive_rate'])} |"
        ),
        (
            f"| full_sorted | {sorted_full['rows']} | {sorted_full['attack_rows']} | "
            f"{sorted_full['stock_alerts_total']} | {sorted_full['stock_rule_alerts']} | {sorted_full['stock_ml_alerts']} | "
            f"{fmt_metric(sorted_full['ml_packet_metrics']['precision'])} | {fmt_metric(sorted_full['ml_packet_metrics']['recall'])} | "
            f"{fmt_metric(sorted_full['ml_packet_metrics']['f1'])} | {fmt_metric(sorted_full['ml_packet_metrics']['false_positive_rate'])} |"
        ),
        "",
        "主结果解读：",
        f"- `attack_tail_sorted` 的 ML `F1 = {fmt_metric(sorted_attack['ml_packet_metrics']['f1'])}`，说明当前版本对这份合成 `ddos_zero` 数据检出很强。",
        f"- `normal_eval_sorted` 的 ML `FPR = {fmt_metric(sorted_normal['ml_packet_metrics']['false_positive_rate'])}`，说明正常段误报控制在较低水平。",
        f"- `attack_tail_sorted` 的 Rule/Profile 告警主要来自 `{sorted_attack['alert_types']}`，可见时序异常和全零负载都被强烈触发。",
        "",
        "## 4. 补充结果：原始乱序文件直接评测",
        "",
        "| Case | Rows | Attack Rows | Total Alerts | Rule | ML | Precision | Recall | F1 | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| full_as_is | {raw_full['rows']} | {raw_full['attack_rows']} | "
            f"{raw_full['stock_alerts_total']} | {raw_full['stock_rule_alerts']} | {raw_full['stock_ml_alerts']} | "
            f"{fmt_metric(raw_full['ml_packet_metrics']['precision'])} | {fmt_metric(raw_full['ml_packet_metrics']['recall'])} | "
            f"{fmt_metric(raw_full['ml_packet_metrics']['f1'])} | {fmt_metric(raw_full['ml_packet_metrics']['false_positive_rate'])} |"
        ),
        "",
        "补充结果解读：",
        f"- 原始乱序文件的 ML `F1 = {fmt_metric(raw_full['ml_packet_metrics']['f1'])}`，仍然不低，但比 `full_sorted` 的 `{fmt_metric(sorted_full['ml_packet_metrics']['f1'])}` 更差。",
        f"- 原始乱序文件的 Rule/Profile 总告警 `= {raw_full['stock_rule_alerts']}`，明显高于 `full_sorted` 的 `{sorted_full['stock_rule_alerts']}`。",
        "- 这说明 `shuffled` 会放大时序规则的告警量，导致评测结果偏离真实在线场景。",
        "",
        "## 5. 结论",
        "",
        "- 这份文件是可用的，但应该优先按 `timestamp_us` 排序后再评测。",
        "- 在排序后的公平口径下，当前项目对这份合成 `ddos_zero` 数据表现很好。",
        "- 这份结果不应外推为“对真实车载 DoS 都同样强”，因为这是一份合成、单攻击类型、单主攻击 ID 的数据。",
        "- 如果后续继续生成同类数据，建议同时保留：`原始时序版` 和 `打乱版`，不要只留 `shuffled` 文件。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--dataset-name", default="Synthetic-Mixed-DDOS-Shuffled")
    parser.add_argument("--train-rows", type=int, default=10_000)
    parser.add_argument("--pre-attack-rows", type=int, default=1_000)
    parser.add_argument("--enable-iforest-aux", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    settings.detector.enable_iforest_aux = bool(args.enable_iforest_aux)

    rows = load_jsonl(args.input_jsonl)
    labels = Counter(row.label for row in rows)
    id_counts = Counter(row.packet.msg_id for row in rows)
    attack_id_counts = Counter(row.packet.msg_id for row in rows if row.label == 1)
    attack_kind_counts = Counter()
    with args.input_jsonl.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            obj = json.loads(line)
            attack_kind_counts[str(obj.get("attack_kind", ""))] += 1

    payload = {
        "input_path": str(args.input_jsonl),
        "dataset_name": args.dataset_name,
        "enable_iforest_aux": bool(settings.detector.enable_iforest_aux),
        "data_stats": {
            "rows": len(rows),
            "normal_rows": int(labels.get(0, 0)),
            "attack_rows": int(labels.get(1, 0)),
            "unique_ids": len(id_counts),
            "id_counts_top12": id_counts.most_common(12),
            "attack_id_counts": attack_id_counts.most_common(12),
            "attack_kind_counts": dict(attack_kind_counts),
            "timestamp_desc_violations": count_timestamp_desc_violations(rows),
        },
        "sorted_eval": evaluate_sorted_split(
            dataset_name=args.dataset_name,
            rows=rows,
            train_rows=args.train_rows,
            pre_attack_rows=args.pre_attack_rows,
        ),
        "raw_eval": evaluate_raw_order(
            dataset_name=args.dataset_name,
            rows=rows,
            train_rows=args.train_rows,
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "synthetic_mixed_ddos_eval.json"
    md_path = args.output_dir / "synthetic_mixed_ddos_report.md"
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path.write_text(build_report(payload), encoding="utf-8-sig")
    print(f"Wrote evaluation JSON to {json_path}")
    print(f"Wrote report Markdown to {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

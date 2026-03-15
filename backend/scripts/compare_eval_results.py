"""Compare two GatewayGuard evaluation JSON files and write a Markdown diff report."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_results(path: Path) -> dict[tuple[str, str], dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {(item["dataset"], item["case"]): item for item in payload["results"]}


def fmt_metric(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def diff_alert_types(old_types: dict, new_types: dict) -> list[str]:
    keys = sorted(set(old_types) | set(new_types))
    changes = []
    for key in keys:
        old = int(old_types.get(key, 0))
        new = int(new_types.get(key, 0))
        if old == new:
            continue
        sign = "+" if new - old > 0 else ""
        changes.append(f"`{key}`: {old} -> {new} ({sign}{new - old})")
    return changes


def build_report(old_path: Path, new_path: Path) -> str:
    old_results = load_results(old_path)
    new_results = load_results(new_path)
    keys = sorted(set(old_results) & set(new_results))

    normal_rows = []
    attack_rows = []
    total_delta = 0
    ml_delta = 0

    for key in keys:
        old = old_results[key]
        new = new_results[key]
        row = {
            "dataset": key[0],
            "case": key[1],
            "old_total": int(old["stock_alerts_total"]),
            "new_total": int(new["stock_alerts_total"]),
            "delta_total": int(new["stock_alerts_total"]) - int(old["stock_alerts_total"]),
            "old_rule": int(old["stock_rule_alerts"]),
            "new_rule": int(new["stock_rule_alerts"]),
            "old_ml": int(old["stock_ml_alerts"]),
            "new_ml": int(new["stock_ml_alerts"]),
            "old_precision": old["ml_packet_metrics"]["precision"],
            "new_precision": new["ml_packet_metrics"]["precision"],
            "old_recall": old["ml_packet_metrics"]["recall"],
            "new_recall": new["ml_packet_metrics"]["recall"],
            "old_f1": old["ml_packet_metrics"]["f1"],
            "new_f1": new["ml_packet_metrics"]["f1"],
            "type_changes": diff_alert_types(old.get("alert_types", {}), new.get("alert_types", {})),
        }
        total_delta += row["delta_total"]
        ml_delta += row["new_ml"] - row["old_ml"]
        if row["case"] == "normal_eval":
            normal_rows.append(row)
        else:
            attack_rows.append(row)

    biggest_up = sorted(keys, key=lambda k: new_results[k]["stock_alerts_total"] - old_results[k]["stock_alerts_total"], reverse=True)[:3]
    biggest_down = sorted(keys, key=lambda k: new_results[k]["stock_alerts_total"] - old_results[k]["stock_alerts_total"])[:3]

    lines = [
        "# 外部评测差异报告",
        "",
        "## 1. 对比对象",
        "",
        f"- 旧结果：`{old_path}`",
        f"- 新结果：`{new_path}`",
        "",
        "## 2. 总体变化",
        "",
        f"- 共同 case 数：`{len(keys)}`",
        f"- 总告警量变化：`{total_delta:+d}`",
        f"- ML 告警量变化：`{ml_delta:+d}`",
        "",
        "告警总量增幅最大的 3 个 case：",
    ]
    for key in biggest_up:
        delta = int(new_results[key]["stock_alerts_total"]) - int(old_results[key]["stock_alerts_total"])
        lines.append(f"- `{key[0]} / {key[1]}`: `{delta:+d}`")
    lines.extend(["", "告警总量降幅最大的 3 个 case："])
    for key in biggest_down:
        delta = int(new_results[key]["stock_alerts_total"]) - int(old_results[key]["stock_alerts_total"])
        lines.append(f"- `{key[0]} / {key[1]}`: `{delta:+d}`")

    lines.extend([
        "",
        "## 3. 正常流量差异",
        "",
        "| 数据集 | 旧总告警 | 新总告警 | 差值 | 旧 Rule | 新 Rule | 旧 ML | 新 ML |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in normal_rows:
        lines.append(
            f"| {row['dataset']} | {row['old_total']} | {row['new_total']} | {row['delta_total']:+d} | "
            f"{row['old_rule']} | {row['new_rule']} | {row['old_ml']} | {row['new_ml']} |"
        )

    lines.extend([
        "",
        "## 4. 攻击流量差异",
        "",
        "| 数据集 | Case | 旧总告警 | 新总告警 | 差值 | 旧 Rule | 新 Rule | 旧 ML | 新 ML | 旧 Recall | 新 Recall |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in attack_rows:
        lines.append(
            f"| {row['dataset']} | {row['case']} | {row['old_total']} | {row['new_total']} | {row['delta_total']:+d} | "
            f"{row['old_rule']} | {row['new_rule']} | {row['old_ml']} | {row['new_ml']} | "
            f"{fmt_metric(row['old_recall'])} | {fmt_metric(row['new_recall'])} |"
        )

    lines.extend(["", "## 5. 逐 case 告警类型变化", ""])
    for row in normal_rows + attack_rows:
        lines.append(f"### {row['dataset']} / {row['case']}")
        if not row["type_changes"]:
            lines.append("")
            lines.append("- 无告警类型变化")
            lines.append("")
            continue
        lines.append("")
        for change in row["type_changes"]:
            lines.append(f"- {change}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-json", type=Path, required=True)
    parser.add_argument("--new-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(args.old_json, args.new_json)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(report, encoding="utf-8")
    print(f"Wrote comparison report to {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

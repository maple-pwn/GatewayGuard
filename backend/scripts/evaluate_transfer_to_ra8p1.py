"""Cross-dataset transfer evaluation from one public CAN dataset to RA8P1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from app.services.anomaly_detector import AnomalyDetectorService
from evaluate_external_can_datasets import (
    build_profiles,
    skip_and_take,
    summarize_case,
    take_attack_window,
    take_first,
    take_last,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--datasets-root",
        type=Path,
        default=PROJECT_ROOT.parent / "datasets",
        help="Root directory containing downloaded public datasets.",
    )
    parser.add_argument(
        "--train-dataset",
        default="B-CAN",
        help="Source dataset used for normal-only training.",
    )
    parser.add_argument(
        "--train-rows",
        type=int,
        default=100_000,
        help="Maximum normal rows used for source-domain training.",
    )
    parser.add_argument(
        "--eval-rows",
        type=int,
        default=100_000,
        help="Maximum window size used for RA8P1 evaluation.",
    )
    parser.add_argument(
        "--ra8p1-jsonl",
        type=Path,
        default=PROJECT_ROOT.parent / "ra8p1_flow_20260312_232920.jsonl",
        help="Optional local RA8P1 JSONL export.",
    )
    parser.add_argument(
        "--ra8p1-csv",
        type=Path,
        default=PROJECT_ROOT.parent / "ra8p1_flow_20260312_232920_partial.csv",
        help="Local RA8P1 CSV export.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=PROJECT_ROOT / "reports" / "ra8p1_transfer_eval.json",
        help="Where to save the transfer-evaluation JSON summary.",
    )
    args = parser.parse_args()

    profiles = build_profiles(
        args.datasets_root,
        ra8p1_jsonl_path=args.ra8p1_jsonl,
        ra8p1_csv_path=args.ra8p1_csv,
    )
    profiles_by_name = {profile.name: profile for profile in profiles}

    if args.train_dataset not in profiles_by_name:
        available = ", ".join(sorted(profiles_by_name))
        print(f"Training dataset {args.train_dataset!r} not found. Available: {available}")
        return 1

    transfer_targets = [
        name for name in ("RA8P1-CSV", "RA8P1-JSONL+CSV") if name in profiles_by_name
    ]
    if not transfer_targets:
        print("No RA8P1 profiles found.")
        return 1

    train_profile = profiles_by_name[args.train_dataset]
    train_samples = take_first(train_profile.train_factory, args.train_rows)
    if not train_samples:
        print(f"No train samples found for {args.train_dataset}.")
        return 1

    detector = AnomalyDetectorService()
    detector.train([sample.packet for sample in train_samples])
    train_ids = {sample.packet.msg_id for sample in train_samples}

    results: list[dict] = []
    target_summaries: list[dict] = []

    for target_name in transfer_targets:
        profile = profiles_by_name[target_name]
        target_train_pool = take_first(profile.train_factory, args.train_rows)
        target_ids = {sample.packet.msg_id for sample in target_train_pool}
        overlap = train_ids & target_ids

        target_summary = {
            "dataset": target_name,
            "target_normal_rows_available": len(target_train_pool),
            "target_unique_ids": len(target_ids),
            "shared_ids_with_train": len(overlap),
            "shared_id_ratio_vs_target": round(len(overlap) / len(target_ids), 4)
            if target_ids
            else 0.0,
            "shared_id_ratio_vs_train": round(len(overlap) / len(train_ids), 4)
            if train_ids
            else 0.0,
            "shared_ids_sample": sorted(list(overlap))[:20],
        }
        target_summaries.append(target_summary)

        normal_eval_samples = skip_and_take(
            profile.normal_eval_factory,
            args.train_rows,
            args.eval_rows,
        )
        if not normal_eval_samples:
            fallback_rows = min(args.eval_rows, max(1, len(target_train_pool)))
            normal_eval_samples = take_last(profile.normal_eval_factory, fallback_rows)
        if normal_eval_samples:
            results.append(
                summarize_case(
                    detector=detector,
                    dataset_name=target_name,
                    case_name="normal_eval_transfer",
                    labeled_packets=normal_eval_samples,
                )
            )

        for case_name, factory in profile.attack_factories.items():
            attack_eval_samples = take_attack_window(factory, args.eval_rows)
            if not attack_eval_samples:
                continue
            results.append(
                summarize_case(
                    detector=detector,
                    dataset_name=target_name,
                    case_name=f"{case_name}_transfer",
                    labeled_packets=attack_eval_samples,
                )
            )

    payload = {
        "train_dataset": args.train_dataset,
        "train_rows": args.train_rows,
        "train_samples_used": len(train_samples),
        "train_unique_ids": len(train_ids),
        "eval_rows": args.eval_rows,
        "datasets_root": str(args.datasets_root),
        "ra8p1_jsonl": str(args.ra8p1_jsonl) if args.ra8p1_jsonl else None,
        "ra8p1_csv": str(args.ra8p1_csv),
        "targets": target_summaries,
        "results": results,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {len(results)} transfer case summaries to {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Evaluate GatewayGuard by fitting on each dataset's train window and testing that same train window."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.services.anomaly_detector import AnomalyDetectorService
from evaluate_external_can_datasets import (
    build_profiles,
    summarize_case,
    take_attack_window,
    take_first,
)


def run_trainset_fit(
    training_mode: str,
    train_rows: int,
    eval_rows: int,
    datasets_root: Path,
    ra8p1_jsonl: Optional[Path],
    ra8p1_csv: Optional[Path],
) -> List[dict]:
    profiles = build_profiles(
        datasets_root,
        ra8p1_jsonl_path=ra8p1_jsonl,
        ra8p1_csv_path=ra8p1_csv,
    )
    results: List[dict] = []

    for profile in profiles:
        if training_mode == "normal_train_fit":
            train_samples = take_first(profile.train_factory, train_rows)
            if not train_samples:
                continue

            detector = AnomalyDetectorService()
            detector.train([sample.packet for sample in train_samples])

            results.append(
                summarize_case(
                    detector=detector,
                    dataset_name=profile.name,
                    case_name="trainset_fit",
                    labeled_packets=train_samples,
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
                        case_name=f"{case_name}_after_trainset_fit",
                        labeled_packets=attack_eval_samples,
                    )
                )
            continue

        if training_mode == "mixed_original":
            for case_name, factory in profile.attack_factories.items():
                mixed_samples = take_attack_window(factory, eval_rows)
                if not mixed_samples:
                    continue

                detector = AnomalyDetectorService()
                detector.train([sample.packet for sample in mixed_samples])

                results.append(
                    summarize_case(
                        detector=detector,
                        dataset_name=profile.name,
                        case_name=f"{case_name}_mixed_original_fit",
                        labeled_packets=mixed_samples,
                    )
                )
            continue

        raise ValueError(f"Unsupported training mode: {training_mode}")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--datasets-root",
        type=Path,
        default=Path(__file__).resolve().parents[2].parent / "datasets",
    )
    parser.add_argument("--train-rows", type=int, default=100_000)
    parser.add_argument("--eval-rows", type=int, default=100_000)
    parser.add_argument(
        "--training-mode",
        choices=("normal_train_fit", "mixed_original"),
        default="normal_train_fit",
    )
    parser.add_argument("--ra8p1-jsonl", type=Path, default=None)
    parser.add_argument("--ra8p1-csv", type=Path, default=None)
    parser.add_argument("--enable-iforest-aux", action="store_true")
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()

    settings.detector.enable_iforest_aux = bool(args.enable_iforest_aux)
    results = run_trainset_fit(
        training_mode=args.training_mode,
        train_rows=args.train_rows,
        eval_rows=args.eval_rows,
        datasets_root=args.datasets_root,
        ra8p1_jsonl=args.ra8p1_jsonl,
        ra8p1_csv=args.ra8p1_csv,
    )

    payload = {
        "datasets_root": str(args.datasets_root),
        "training_mode": args.training_mode,
        "train_rows": args.train_rows,
        "eval_rows": args.eval_rows,
        "enable_iforest_aux": bool(settings.detector.enable_iforest_aux),
        "results": results,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {len(results)} trainset-fit case summaries to {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

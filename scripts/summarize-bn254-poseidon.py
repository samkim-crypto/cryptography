#!/usr/bin/env python3
"""Summarize fetched ABBA measurements; positive percentages mean faster."""

import argparse
import json
import math
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="Fetched outputs/poseidon-experiment-results directory")
    args = parser.parse_args()
    metadata = json.loads((args.results / "metadata.json").read_text())
    summary = json.loads((args.results / "summary.json").read_text())
    output = {"experiment": metadata["experiment"], "seed": metadata["seed"], "configurations": {}}
    for config, rows in summary.items():
        result = {}
        for family in ["poseidon_bytes", "poseidon_typed", "scalar_arithmetic", "ifma_arithmetic"]:
            selected = [row for row in rows if row["case"].startswith(family + "_")
                        or row["case"].startswith(family + "/")]
            if not selected:
                continue
            result[family] = {
                "cases": len(selected),
                "geomean_improvement_pct": 100 * (1 - math.exp(sum(
                    math.log(row["candidate_ns"] / row["baseline_ns"]) for row in selected) / len(selected))),
                "min_improvement_pct": min(row["improvement_pct"] for row in selected),
                "max_improvement_pct": max(row["improvement_pct"] for row in selected),
                "separated_improvements": sum(row["all_candidate_intervals_below_baseline"] for row in selected),
                "separated_regressions": sum(row["all_candidate_intervals_above_baseline"] for row in selected),
                "rows": [{key: row[key] for key in ["case", "baseline_ns", "candidate_ns", "improvement_pct",
                                                    "all_candidate_intervals_below_baseline",
                                                    "all_candidate_intervals_above_baseline"]} for row in selected],
            }
        path = args.results / config / "comparison.json"
        if path.exists():
            measured = json.loads(path.read_text())
            result["comparison"] = {"variant": metadata["comparison_variant"], "rows": []}
            for width in range(2, 14):
                prefix = f"poseidon_bytes_t{width}/"
                if prefix + "solana-bn254" not in measured:
                    continue
                values = {impl: measured[prefix + impl]["ns"]
                          for impl in ["solana-bn254", "light-poseidon", "firedancer"]}
                result["comparison"]["rows"].append({"inputs": width - 1, "ns": values,
                    "speedup_vs_light": values["light-poseidon"] / values["solana-bn254"],
                    "speedup_vs_firedancer": values["firedancer"] / values["solana-bn254"]})
        output["configurations"][config] = result
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

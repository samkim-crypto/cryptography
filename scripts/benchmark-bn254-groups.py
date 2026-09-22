#!/usr/bin/env python3
"""Checkpoint G1/G2 candidates locally; test and measure ABBA through benchctl."""

import argparse
import base64
import difflib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "group-experiment-results"
FLAGS = {
    "generic": "-C target-cpu=x86-64",
    "native_scalar": "-C target-cpu=native -C target-feature=-avx512ifma",
    "native": "-C target-cpu=native",
}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checkpoint = load("group_checkpoints", "benchmark-bn254-experiment.py")
checkpoint.INPUTS = ROOT / ".benchctl-inputs/group-experiments"
runner = load("group_comparator", "benchmark-bn254-pairing.py")


def build(command, bench):
    command = list(command)
    command[command.index("--bench") + 1] = bench
    executable = None
    print("BUILD", command, flush=True)
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            event = json.loads(line)
            if event.get("reason") == "compiler-message":
                print(event["message"].get("rendered", ""), end="", flush=True)
            if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == bench:
                executable = event.get("executable") or executable
        if process.wait():
            raise SystemExit(process.returncode)
    if executable is None:
        raise RuntimeError(f"Cargo did not report {bench}")
    return Path(executable)


def estimates(directory):
    found = {}
    for path in sorted(directory.glob("**/new/estimates.json")):
        case = "/".join(path.relative_to(directory).parts[:-2])
        raw = json.loads(path.read_text())
        estimator = "slope" if raw.get("slope") is not None else "mean"
        value = raw[estimator]
        found[case] = {
            "ns": value["point_estimate"],
            "low_ns": value["confidence_interval"]["lower_bound"],
            "high_ns": value["confidence_interval"]["upper_bound"],
            "estimator": estimator,
        }
    if not found:
        raise RuntimeError(f"No measured cases in {directory}")
    return found


def summarize(rounds):
    keys = set(rounds[0]["estimates"])
    if any(set(r["estimates"]) != keys for r in rounds):
        raise RuntimeError("Measured cases differ between ABBA rounds")
    rows = []
    for case in sorted(keys):
        values = {v: [r["estimates"][case] for r in rounds if r["variant"] == v]
                  for v in ["baseline", "candidate"]}
        before = math.sqrt(math.prod(v["ns"] for v in values["baseline"]))
        after = math.sqrt(math.prod(v["ns"] for v in values["candidate"]))
        rows.append({
            "case": case, "baseline_ns": before, "candidate_ns": after,
            "improvement_pct": 100 * (1 - after / before),
            "all_candidate_intervals_below_baseline":
                max(v["high_ns"] for v in values["candidate"]) < min(v["low_ns"] for v in values["baseline"]),
            "all_candidate_intervals_above_baseline":
                min(v["low_ns"] for v in values["candidate"]) > max(v["high_ns"] for v in values["baseline"]),
            "rounds": values,
        })
    return rows


def measure(binary, directory, case_filter, args):
    command = [str(binary), "--bench", case_filter, "--noplot",
               "--sample-size", str(args.samples), "--warm-up-time", str(args.warmup),
               "--measurement-time", str(args.measurement)]
    runner.execute(command, env=dict(os.environ, CRITERION_HOME=str(directory)))
    return estimates(directory)


def run(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Run builds/tests/benchmarks through benchctl on the x86 devserver")
    os.chdir(ROOT)
    if args.seed is not None:
        if not 0 <= args.seed < 1 << 64:
            raise SystemExit("Seed must fit u64")
        os.environ["BN254_GROUP_BENCH_SEED"] = str(args.seed)
    manifest = json.loads((checkpoint.INPUTS / f"{args.id}.json").read_text())
    baseline = {name: base64.b64decode(item["bytes"]) if item["bytes"] is not None else None
                for name, item in manifest["files"].items()}
    candidate = {name: checkpoint.read(checkpoint.checked_path(name)) for name in baseline}
    for name, data in baseline.items():
        if checkpoint.sha(data) != manifest["files"][name]["sha256"]:
            raise SystemExit(f"Invalid checkpoint: {name}")
    if candidate == baseline:
        raise SystemExit("Candidate matches baseline")
    OUTPUT.mkdir(exist_ok=False)
    metadata = {
        "experiment": args.id, "schedule": ["baseline", "candidate", "candidate", "baseline"],
        "files": {name: {"baseline": checkpoint.sha(baseline[name]), "candidate": checkpoint.sha(candidate[name])}
                  for name in baseline},
        "seed_override": os.environ.get("BN254_GROUP_BENCH_SEED"),
        "runner_sha256": checkpoint.sha(Path(__file__).read_bytes()),
        "benchmark_sha256": checkpoint.sha((ROOT / "syscall/solana-bn254/benches/group_compare.rs").read_bytes()),
        "configurations": {},
        "filter": args.filter, "pairing_filter": args.pairing_filter if args.pairing else None,
        "samples": args.samples, "warmup": args.warmup, "measurement": args.measurement,
        "comparison": {"variant": args.comparison_variant, "filter": args.comparison_filter}
                      if args.comparison else None,
    }
    def save():
        (OUTPUT / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    save()
    patch = "".join("".join(difflib.unified_diff(
        (baseline[name] or b"").decode().splitlines(keepends=True),
        (candidate[name] or b"").decode().splitlines(keepends=True),
        fromfile=f"a/{name}", tofile=f"b/{name}")) for name in baseline)
    (OUTPUT / "candidate.patch").write_text(patch)
    original_target = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
    available = sorted(os.sched_getaffinity(0))
    if args.cpu not in available:
        raise SystemExit(f"CPU {args.cpu} not in {available}")
    metadata["cpu"] = args.cpu
    metadata["cpu_affinity_before_pinning"] = available
    reports = {}
    try:
        for config in args.configs:
            config_out = OUTPUT / config
            config_out.mkdir()
            target = original_target / f"groups-{config}"
            target.mkdir(parents=True)
            os.environ["CARGO_TARGET_DIR"] = str(target)
            os.environ["RUSTFLAGS"] = FLAGS[config]
            bins = target / "experiment-binaries"
            bins.mkdir()
            os.sched_setaffinity(0, set(available))
            checkpoint.write_files(baseline)
            # Builds the unchanged baseline and C comparator, then checks all
            # three byte implementations even if the timing filter is narrower.
            runner.run(argparse.Namespace(
                archive=args.archive, cc="gcc", test=False, bench="group_compare",
                criterion_args=["--test"],
            ))
            native = json.loads((ROOT / "group-comparison-metadata.json").read_text())
            metadata["configurations"][config] = native
            save()
            shutil.copy2(native["benchmark_command"][0], bins / "baseline")
            if args.pairing:
                shutil.copy2(build(native["cargo_command"], "pairing_compare"), bins / "baseline-pairing")
                runner.execute([str(bins / "baseline-pairing"), "--bench", "--test"])
            checkpoint.write_files(candidate)
            runner.execute(["cargo", "test", "--locked", "-p", "solana-bn254", "--lib", "--tests"])
            shutil.copy2(build(native["cargo_command"], "group_compare"), bins / "candidate")
            runner.execute([str(bins / "candidate"), "--bench", "--test"])
            if args.pairing:
                shutil.copy2(build(native["cargo_command"], "pairing_compare"), bins / "candidate-pairing")
                runner.execute([str(bins / "candidate-pairing"), "--bench", "--test"])
            native["binaries"] = {p.name: checkpoint.sha(p.read_bytes()) for p in bins.iterdir()}
            # Capture emitted implementation code in the same queued job.
            for variant in ["baseline", "candidate"]:
                with (config_out / f"{variant}-symbols.txt").open("w") as out:
                    subprocess.run(["nm", "-S", "--size-sort", "-C", str(bins / variant)], stdout=out, check=True)
                disassembly = subprocess.check_output(["objdump", "-d", "-C", str(bins / variant)], text=True)
                blocks = re.split(r"\n(?=[0-9a-f]+ <)", disassembly)
                (config_out / f"{variant}-assembly.txt").write_text("\n".join(
                    block for block in blocks if "solana_bn254::" in block.split("\n", 1)[0]))
            save()
            os.sched_setaffinity(0, {args.cpu})
            if args.comparison:
                values = measure(bins / args.comparison_variant, config_out / "comparison",
                                 args.comparison_filter, args)
                (config_out / "comparison.json").write_text(json.dumps(values, indent=2) + "\n")
            rounds = []
            pairing_rounds = []
            for index, variant in enumerate(metadata["schedule"]):
                print(f"GROUP EXPERIMENT {args.id} {config} round {index + 1}/4 {variant}", flush=True)
                directory = config_out / f"round-{index}-{variant}"
                rounds.append({"variant": variant, "estimates": measure(bins / variant, directory, args.filter, args)})
                if args.pairing:
                    directory = config_out / f"pairing-{index}-{variant}"
                    pairing_rounds.append({"variant": variant, "estimates": measure(
                        bins / f"{variant}-pairing", directory, args.pairing_filter, args)})
            reports[config] = {"groups": summarize(rounds), "pairing": summarize(pairing_rounds) if pairing_rounds else []}
            (OUTPUT / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
            print(json.dumps({"config": config, "results": reports[config]}, indent=2), flush=True)
    finally:
        checkpoint.write_files(candidate)
    save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    local = sub.add_parser("checkpoint")
    local.add_argument("--id", required=True)
    local.add_argument("files", nargs="+")
    undo = sub.add_parser("restore")
    undo.add_argument("--id", required=True)
    undo.add_argument("--results", type=Path, required=True)
    remote = sub.add_parser("run")
    remote.add_argument("--id", required=True)
    remote.add_argument("--archive", type=Path, default=Path(".benchctl-inputs/firedancer-bn254-groups.tar.gz"))
    remote.add_argument("--configs", nargs="+", choices=list(FLAGS), default=["native", "native_scalar", "generic"])
    remote.add_argument("--seed", type=lambda value: int(value, 0))
    remote.add_argument("--cpu", type=int, default=16)
    remote.add_argument("--comparison", action="store_true")
    remote.add_argument("--comparison-variant", choices=["baseline", "candidate"], default="baseline")
    remote.add_argument("--comparison-filter", default="group_")
    remote.add_argument("--pairing", action="store_true")
    remote.add_argument("--filter", default=r"group_bytes_.*/solana-bn254/le$|group_kernel_.*/solana-bn254$")
    remote.add_argument("--pairing-filter", default=r"pairing_bytes_seeded_(1|4|16)/solana-bn254/le$")
    remote.add_argument("--samples", type=int, default=100)
    remote.add_argument("--warmup", type=float, default=1)
    remote.add_argument("--measurement", type=float, default=2)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.id):
        parser.error("Use only letters, numbers, underscore, and hyphen in experiment IDs")
    {"checkpoint": checkpoint.checkpoint, "restore": checkpoint.restore, "run": run}[args.action](args)


if __name__ == "__main__":
    main()

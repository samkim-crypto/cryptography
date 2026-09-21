#!/usr/bin/env python3
"""Checkpoint one change locally; compare its two builds inside a benchctl job."""

import argparse
import base64
import difflib
import hashlib
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
INPUTS = ROOT / ".benchctl-inputs/pairing-experiments"


def sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def checked_path(name):
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT) or any(p in {".git", ".codex", ".agents"} for p in path.relative_to(ROOT).parts):
        raise ValueError(f"Invalid experiment path: {name}")
    return path


def read(path):
    return path.read_bytes() if path.exists() else None


def write_files(files):
    for name, data in files.items():
        path = checked_path(name)
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)


def checkpoint(args):
    INPUTS.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in args.files:
        path = checked_path(name)
        data = read(path)
        files[path.relative_to(ROOT).as_posix()] = {
            "sha256": sha(data),
            "bytes": base64.b64encode(data).decode() if data is not None else None,
        }
    manifest = {"experiment": args.id, "files": files}
    path = INPUTS / f"{args.id}.json"
    with path.open("x") as out:
        json.dump(manifest, out, indent=2)
        out.write("\n")
    print(path)


def restore(args):
    manifest = json.loads((INPUTS / f"{args.id}.json").read_text())
    metadata = json.loads((args.results / "metadata.json").read_text())
    if metadata["experiment"] != args.id or set(metadata["files"]) != set(manifest["files"]):
        raise SystemExit("Result/checkpoint mismatch; nothing restored")
    baseline = {}
    # Check every affected file before writing any. A concurrent edit must not
    # be overwritten merely because it shares a path with this experiment.
    for name, item in manifest["files"].items():
        data = base64.b64decode(item["bytes"]) if item["bytes"] is not None else None
        if sha(data) != item["sha256"] or sha(data) != metadata["files"][name]["baseline"]:
            raise SystemExit(f"Baseline mismatch: {name}; nothing restored")
        if sha(read(checked_path(name))) != metadata["files"][name]["candidate"]:
            raise SystemExit(f"File changed since measurement: {name}; nothing restored")
        baseline[name] = data
    write_files(baseline)
    print(f"Restored {len(baseline)} experiment files; candidate patch remains in {args.results}")


def build(command):
    executable = None
    print("Building candidate:", command, flush=True)
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            event = json.loads(line)
            if event.get("reason") == "compiler-message":
                print(event["message"].get("rendered", ""), end="", flush=True)
            if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == "pairing_compare":
                executable = event.get("executable") or executable
        if process.wait():
            raise SystemExit(process.returncode)
    if executable is None:
        raise RuntimeError("Cargo did not report the benchmark executable")
    return Path(executable)


def estimates(directory, expected, prepared):
    result = {}
    paths = list(directory.glob("pairing_bytes_*/solana-bn254/*/new/estimates.json"))
    if prepared:
        paths.extend(directory.glob("pairing_reused_*/solana-bn254/*/new/estimates.json"))
    for path in sorted(paths):
        case, _, order, _, _ = path.relative_to(directory).parts
        raw = json.loads(path.read_text())
        estimator = "slope" if raw.get("slope") is not None else "mean"
        value = raw[estimator]
        result[f"{case}/{order}"] = {
            "ns": value["point_estimate"],
            "low_ns": value["confidence_interval"]["lower_bound"],
            "high_ns": value["confidence_interval"]["upper_bound"],
            "estimator": estimator,
        }
    if len(result) != expected:
        raise RuntimeError(f"Expected {expected} measurements, received {len(result)}")
    return result


def run(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Run through benchctl on the x86 devserver")
    os.chdir(ROOT)
    manifest = json.loads((INPUTS / f"{args.id}.json").read_text())
    baseline = {
        name: base64.b64decode(item["bytes"]) if item["bytes"] is not None else None
        for name, item in manifest["files"].items()
    }
    candidate = {name: read(checked_path(name)) for name in baseline}
    if candidate == baseline:
        raise SystemExit("No candidate changes relative to checkpoint")
    output = ROOT / "pairing-experiment-results"
    output.mkdir(exist_ok=False)
    bins = Path(os.environ["CARGO_TARGET_DIR"]) / "experiment-binaries"
    bins.mkdir(parents=True, exist_ok=False)
    patch = "".join(
        "".join(difflib.unified_diff(
            (baseline[name] or b"").decode().splitlines(keepends=True),
            (candidate[name] or b"").decode().splitlines(keepends=True),
            fromfile=f"a/{name}", tofile=f"b/{name}",
        )) for name in baseline
    )
    (output / "candidate.patch").write_text(patch)
    metadata = {
        "experiment": args.id,
        "files": {name: {"baseline": sha(baseline[name]), "candidate": sha(candidate[name])} for name in baseline},
        "schedule": ["baseline", "candidate", "candidate", "baseline"],
    }
    # Failed builds/tests still need hashes for a guarded local restoration.
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    spec = importlib.util.spec_from_file_location("pairing_runner", ROOT / "scripts/benchmark-bn254-pairing.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Compile both variants in the same frozen job, using identical dependencies
    # and flags. The baseline's existing adapter checks all three implementations.
    try:
        write_files(baseline)
        module.run(argparse.Namespace(
            archive=Path(module.DEFAULT_ARCHIVE), cc="gcc", test=False,
            criterion_args=["--test"],
        ))
        native = json.loads((ROOT / "pairing-comparison-metadata.json").read_text())
        shutil.copy2(native["benchmark_command"][0], bins / "baseline")
    finally:
        write_files(candidate)
    module.execute(["cargo", "test", "--locked", "-p", "solana-bn254", "--lib", "--tests"])
    executable = build(native["cargo_command"])
    shutil.copy2(executable, bins / "candidate")
    module.execute([str(bins / "candidate"), "--bench", "--test"])
    metadata["build"] = native
    metadata["binaries"] = {name: sha((bins / name).read_bytes()) for name in ["baseline", "candidate"]}
    # Preserve emitted code for later inlining/register-pressure review. These
    # read-only tools run inside the same remote queue before any timing round.
    for variant in ["baseline", "candidate"]:
        for tool, options, suffix in [
            ("size", ["-A"], "sections.txt"),
            ("nm", ["-S", "--size-sort", "-C"], "symbols.txt"),
            ("objdump", ["-d", "-C"], "assembly.txt"),
        ]:
            if shutil.which(tool):
                result = subprocess.run([tool, *options, str(bins / variant)],
                                        text=True, capture_output=True, check=False)
                content = result.stdout
                if tool == "objdump" and result.returncode == 0:
                    blocks = re.split(r"\n(?=[0-9a-f]+ <)", content)
                    content = "\n".join(block for block in blocks
                                        if "solana_bn254::" in block.split("\n", 1)[0])
                (output / f"{variant}-{suffix}").write_text(content + result.stderr)
    available = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else available[len(available) // 4]
    if cpu not in available:
        raise RuntimeError(f"CPU {cpu} unavailable; allowed: {available}")
    metadata["cpu"] = cpu
    metadata["cpu_affinity_before_pinning"] = available
    os.sched_setaffinity(0, {cpu})
    case_filter = "pairing_(bytes|reused)_.*/solana-bn254/" if args.prepared else "pairing_bytes_.*/solana-bn254/"
    criterion_args = [
        "--bench", case_filter, "--noplot", "--sample-size", str(args.samples),
        "--warm-up-time", str(args.warmup), "--measurement-time", str(args.measurement),
    ]
    metadata["criterion_args"] = criterion_args
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rounds = []
    for index, variant in enumerate(metadata["schedule"]):
        directory = output / f"round-{index}-{variant}"
        env = dict(os.environ, CRITERION_HOME=str(directory))
        print(f"EXPERIMENT {args.id}: round {index + 1}/4, {variant}, CPU {cpu}", flush=True)
        module.execute([str(bins / variant), *criterion_args], env=env)
        rounds.append({"variant": variant, "estimates": estimates(directory, args.expected_cases, args.prepared)})
    rows = []
    for case in rounds[0]["estimates"]:
        values = {variant: [r["estimates"][case]["ns"] for r in rounds if r["variant"] == variant]
                  for variant in ["baseline", "candidate"]}
        before = math.sqrt(math.prod(values["baseline"]))
        after = math.sqrt(math.prod(values["candidate"]))
        rows.append({"case": case, "baseline_ns": before, "candidate_ns": after,
                     "improvement_pct": 100 * (1 - after / before), "rounds": values})
    ordinary = [row for row in rows if "/" in row["case"] and "pairing_bytes_seeded_" in row["case"] and "seeded_0/" not in row["case"]]
    ratio = math.exp(sum(math.log(row["candidate_ns"] / row["baseline_ns"]) for row in ordinary) / len(ordinary))
    report = {"experiment": args.id, "seeded_geomean_improvement_pct": 100 * (1 - ratio),
              "measurements": rows, "rounds": rounds}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.prepared:
        # Cold preparation has no equivalent pre-API baseline. Measure its
        # absolute cost separately, never include it in warm improvement ratios.
        cold_args = list(criterion_args)
        cold_args[1] = "pairing_preparation/"
        env = dict(os.environ, CRITERION_HOME=str(output / "preparation"))
        module.execute([str(bins / "candidate"), *cold_args], env=env)
    if args.profile:
        if shutil.which("perf"):
            for variant in ["baseline", "candidate"]:
                env = dict(os.environ, BN254_PROFILE_ITERATIONS="5000")
                command = ["perf", "stat", "-x", ";", "-e",
                           "cycles:u,instructions:u,cache-references:u,cache-misses:u",
                           "-o", str(output / f"{variant}-perf.csv"),
                           "--", str(bins / variant)]
                result = subprocess.run(command, env=env, text=True, capture_output=True,
                                        check=False, timeout=180)
                (output / f"{variant}-perf.log").write_text(
                    f"exit_code={result.returncode}\n" + result.stdout + result.stderr)
        else:
            (output / "perf-unavailable.txt").write_text("perf is not installed\n")
    print(json.dumps({k: v for k, v in report.items() if k != "rounds"}, indent=2), flush=True)


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
    remote.add_argument("--cpu", type=int)
    remote.add_argument("--profile", action="store_true")
    remote.add_argument("--prepared", action="store_true")
    remote.add_argument("--expected-cases", type=int, default=36)
    remote.add_argument("--samples", type=int, default=100)
    remote.add_argument("--warmup", type=float, default=1)
    remote.add_argument("--measurement", type=float, default=3)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.id):
        parser.error("Experiment id must contain only letters, numbers, underscore, or hyphen")
    {"checkpoint": checkpoint, "restore": restore, "run": run}[args.action](args)


if __name__ == "__main__":
    main()

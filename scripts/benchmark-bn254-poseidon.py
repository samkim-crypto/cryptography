#!/usr/bin/env python3
"""Checkpoint Poseidon trials locally; build, test and measure through benchctl."""

import argparse
import base64
import difflib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import importlib.util


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("poseidon_helpers", ROOT / "scripts/benchmark-bn254-groups.py")
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
checkpoint = helpers.checkpoint
checkpoint.INPUTS = ROOT / ".benchctl-inputs/poseidon-experiments"
runner = helpers.runner
OUTPUT = ROOT / "poseidon-experiment-results"


def run(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Run builds/tests/benchmarks through benchctl on the x86 devserver")
    os.chdir(ROOT)
    os.environ["BN254_POSEIDON_BENCH_SEED"] = str(args.seed)
    if args.regressions:
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
        "seed": args.seed, "cpu": args.cpu,
        "runner_sha256": checkpoint.sha(Path(__file__).read_bytes()),
        "benchmark_sha256": checkpoint.sha((ROOT / "syscall/solana-bn254/benches/poseidon_bench.rs").read_bytes()),
        "configurations": {}, "filter": args.filter,
        "samples": args.samples, "warmup": args.warmup, "measurement": args.measurement,
        "comparison_variant": args.comparison,
        "ark_asm": args.ark_asm,
        "regressions": args.regressions,
        "regression_seeds": {"groups": args.seed, "pairing": "fixed seed in benches/common/pairing.rs"}
                            if args.regressions else None,
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
    metadata["cpu_affinity_before_pinning"] = available
    reports = {}
    try:
        for config in args.configs:
            config_out = OUTPUT / config
            config_out.mkdir()
            os.environ["RUSTFLAGS"] = helpers.FLAGS[config]
            os.sched_setaffinity(0, set(available))
            builds = {}
            binaries = {}
            for variant, files in [("baseline", baseline), ("candidate", candidate)]:
                checkpoint.write_files(files)
                # Separate targets ensure an archived source timestamp cannot
                # make Cargo reuse another variant's compiled crate.
                target = original_target / f"poseidon-{config}-{variant}"
                target.mkdir(parents=True)
                os.environ["CARGO_TARGET_DIR"] = str(target)
                runner.run(argparse.Namespace(
                    archive=args.archive, cc="gcc", test=False, bench="poseidon_bench",
                    ark_asm=args.ark_asm,
                    criterion_args=["--test"],
                ))
                native = json.loads((ROOT / "poseidon-comparison-metadata.json").read_text())
                builds[variant] = native
                binary = target / "experiment-binary"
                shutil.copy2(native["benchmark_command"][0], binary)
                binaries[variant] = binary
                native["binary_sha256"] = checkpoint.sha(binary.read_bytes())
                metadata["configurations"][config] = builds
                save()
                if variant == "candidate":
                    test_command = ["cargo", "test", "--locked", "-p", "solana-bn254", "--lib", "--tests"]
                    if args.ark_asm:
                        test_command += ["--features", "ark-ff/asm"]
                    runner.execute(test_command)
                if args.regressions:
                    for bench in ["group_compare", "pairing_compare"]:
                        regression = target / f"experiment-{bench}"
                        shutil.copy2(helpers.build(native["cargo_command"], bench), regression)
                        runner.execute([str(regression), "--bench", "--test"])
                        binaries[f"{variant}-{bench}"] = regression
                        native[f"{bench}_sha256"] = checkpoint.sha(regression.read_bytes())
                    save()
                with (config_out / f"{variant}-symbols.txt").open("w") as out:
                    subprocess.run(["nm", "-S", "--size-sort", "-C", str(binary)], stdout=out, check=True)
                disassembly = subprocess.check_output(["objdump", "-d", "-C", str(binary)], text=True)
                blocks = re.split(r"\n(?=[0-9a-f]+ <)", disassembly)
                (config_out / f"{variant}-assembly.txt").write_text("\n".join(
                    block for block in blocks if any(name in block.split("\n", 1)[0]
                                                     for name in ["solana_bn254::", "poseidon_bench::"])))
            os.sched_setaffinity(0, {args.cpu})
            if args.comparison:
                values = helpers.measure(binaries[args.comparison], config_out / "comparison", "poseidon_", args)
                (config_out / "comparison.json").write_text(json.dumps(values, indent=2) + "\n")
            rounds = []
            regression_rounds = {"group_compare": [], "pairing_compare": []}
            for index, variant in enumerate(metadata["schedule"]):
                print(f"POSEIDON EXPERIMENT {args.id} {config} round {index + 1}/4 {variant}", flush=True)
                directory = config_out / f"round-{index}-{variant}"
                rounds.append({"variant": variant, "estimates": helpers.measure(binaries[variant], directory, args.filter, args)})
                if args.regressions:
                    for bench, case_filter in [
                        ("group_compare", r"group_bytes_g[12]_(mul_random256|add_random)/solana-bn254/le$"),
                        ("pairing_compare", r"pairing_bytes_seeded_(1|4|16)/solana-bn254/le$"),
                    ]:
                        regression_rounds[bench].append({"variant": variant, "estimates": helpers.measure(
                            binaries[f"{variant}-{bench}"], config_out / f"{bench}-{index}-{variant}", case_filter, args)})
            reports[config] = helpers.summarize(rounds)
            (OUTPUT / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
            if args.regressions:
                (config_out / "regressions.json").write_text(json.dumps(
                    {bench: helpers.summarize(values) for bench, values in regression_rounds.items()}, indent=2) + "\n")
            print(json.dumps({"config": config, "results": reports[config]}, indent=2), flush=True)
    finally:
        checkpoint.write_files(candidate)
        os.sched_setaffinity(0, set(available))
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
    remote.add_argument("--archive", type=Path, default=Path(".benchctl-inputs/firedancer-bn254-poseidon.tar.gz"))
    remote.add_argument("--configs", nargs="+", choices=list(helpers.FLAGS), default=["native", "native_scalar", "generic"])
    remote.add_argument("--seed", type=int, default=41)
    remote.add_argument("--cpu", type=int, default=16)
    remote.add_argument("--comparison", choices=["baseline", "candidate"])
    remote.add_argument("--ark-asm", action="store_true", help="Enable Arkworks' optional native assembly feature")
    remote.add_argument("--regressions", action="store_true", help="Also measure representative G1/G2 and pairing operations")
    remote.add_argument("--filter", default=r"poseidon_.*/solana-bn254$|scalar_arithmetic/")
    remote.add_argument("--samples", type=int, default=100)
    remote.add_argument("--warmup", type=float, default=1)
    remote.add_argument("--measurement", type=float, default=2)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.id):
        parser.error("Use only letters, numbers, underscore, and hyphen in experiment IDs")
    if args.action == "run" and not 0 <= args.seed < 1 << 64:
        parser.error("Seed must fit u64")
    {"checkpoint": checkpoint.checkpoint, "restore": checkpoint.restore, "run": run}[args.action](args)


if __name__ == "__main__":
    main()

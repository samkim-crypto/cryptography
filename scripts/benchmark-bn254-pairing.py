#!/usr/bin/env python3
"""Snapshot local Firedancer source, then build/run the comparison via benchctl.

Only `snapshot` runs locally. Run `run` inside a queued x86 Linux job.
No Firedancer source changes or production Rust dependencies are required.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import tarfile


SOURCE_METADATA = "bn254-benchmark-source.json"
DEFAULT_ARCHIVE = ".benchctl-inputs/firedancer-bn254-native.tar.gz"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def capture(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def execute(command, **kwargs):
    print("+ " + shlex.join(map(str, command)), flush=True)
    subprocess.run(command, check=True, **kwargs)


def snapshot(args):
    root = args.firedancer.resolve()
    sources = sorted((root / "src/ballet/bn254").glob("fd_bn254*.c"))
    if not sources:
        raise SystemExit("No Firedancer BN254 C sources found")
    pending = list(sources)
    files = {}
    while pending:
        path = pending.pop().resolve()
        name = path.relative_to(root).as_posix()
        if name in files:
            continue
        data = path.read_bytes()
        files[name] = data
        for include in re.findall(rb'^\s*#\s*include\s*"([^"]+)"', data, re.M):
            pending.append(path.parent / include.decode())
        # GCC's file-scope inline assembly also includes macros relative to
        # Firedancer's repository root, rather than the including C header.
        for include in re.findall(rb'\.include\s+\\"([^"\\]+)\\"', data):
            pending.append(root / include.decode())
    for path in sorted(root.glob("LICENSE*")):
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    metadata = {
        "repository": str(root),
        "commit": capture(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "tracked_changes": capture(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"]),
        "sources": [path.relative_to(root).as_posix() for path in sources],
        "sha256": {name: digest(data) for name, data in sorted(files.items())},
    }
    files[SOURCE_METADATA] = (json.dumps(metadata, indent=2) + "\n").encode()
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves earlier snapshots; choose a new path to update.
    with args.archive.open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as tar:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    tar.addfile(info, io.BytesIO(data))
    print(json.dumps({
        "archive": str(args.archive),
        "sha256": digest(args.archive.read_bytes()),
        "commit": metadata["commit"],
        "tracked_changes": metadata["tracked_changes"],
        "files": len(files),
        "bytes": args.archive.stat().st_size,
    }, indent=2))


def run(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Run this command on the x86 Linux devserver through benchctl")
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    bench = getattr(args, "bench", "pairing_compare")
    metadata_path = root / ("group-comparison-metadata.json" if bench == "group_compare"
                            else "pairing-comparison-metadata.json")
    archive = args.archive.resolve()
    build = Path(os.environ["CARGO_TARGET_DIR"]).resolve() / "firedancer-pairing"
    build.mkdir(parents=True, exist_ok=False)
    source = build / "source"
    source.mkdir()
    # The snapshot contains regular source files only, never links or devices.
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            path = source / member.name
            if not member.isfile() or not path.resolve().is_relative_to(source):
                raise SystemExit(f"Invalid archive member: {member.name}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(tar.extractfile(member).read())
    source_metadata = json.loads((source / SOURCE_METADATA).read_text())
    for name, expected in source_metadata["sha256"].items():
        if digest((source / name).read_bytes()) != expected:
            raise SystemExit(f"Firedancer source hash mismatch: {name}")

    # Native x86 optimizations, including Firedancer's ADX assembly; the optional
    # external s2n-bignum backend is disabled. No LTO for either implementation.
    cc = args.cc
    cflags = [
        "-std=gnu17", "-O3", "-march=native", "-mtune=native", "-fPIC",
        "-ffp-contract=off", "-fno-math-errno", "-fno-strict-aliasing",
        "-DFD_USING_GCC=1", "-DFD_HAS_OPTIMIZATION=1", "-DFD_HAS_INT128=1",
        "-DFD_HAS_DOUBLE=1", "-DFD_HAS_ALLOCA=1", "-DFD_HAS_X86=1",
        "-DFD_HAS_SSE=1", "-DFD_HAS_AVX=1", "-DFD_HAS_AVX512=1",
        "-DFD_HAS_S2NBIGNUM=0",
    ]
    metadata = {
        "firedancer": source_metadata,
        "firedancer_archive_sha256": digest(archive.read_bytes()),
        "cc": capture([cc, "--version"]),
        "cflags": cflags,
        "rustc": capture(["rustc", "-vV"]),
        "rustflags": os.environ.get("RUSTFLAGS", ""),
        "cargo_lock_sha256": digest((root / "Cargo.lock").read_bytes()),
        "lscpu": capture(["lscpu"]),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "criterion_arguments": args.criterion_args,
        "smoke_test": args.test,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata, indent=2), flush=True)
    objects = []
    for name in source_metadata["sources"]:
        obj = build / (Path(name).stem + ".o")
        execute([cc, *cflags, "-c", str(source / name), "-o", str(obj)], cwd=source)
        objects.append(str(obj))
    execute(["ar", "rcs", str(build / "libfiredancer_bn254.a"), *objects])

    if args.test:
        execute(["cargo", "test", "--locked", "-p", "solana-bn254", "--lib", "--tests"])
    command = [
        "cargo", "rustc", "--locked", "--profile", "bench", "-p", "solana-bn254",
        "--features", "firedancer-bench", "--bench", bench,
        "--message-format=json", "--", "-L", f"native={build}",
    ]
    metadata["cargo_command"] = command
    print("+ " + shlex.join(command), flush=True)
    executable = None
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            event = json.loads(line)
            if event.get("reason") == "compiler-message":
                print(event["message"].get("rendered", ""), end="", flush=True)
            if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == bench:
                executable = event.get("executable") or executable
        if process.wait():
            raise SystemExit(process.returncode)
    if executable is None:
        raise SystemExit("Cargo did not report the benchmark executable")
    criterion_args = args.criterion_args
    if criterion_args[:1] == ["--"]:
        criterion_args = criterion_args[1:]
    command = [executable, "--bench", *(["--test"] if args.test else []), *criterion_args]
    metadata["benchmark_command"] = command
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    execute(command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    local = sub.add_parser("snapshot", help="Archive the C sources and their quoted include dependencies")
    local.add_argument("--firedancer", type=Path, required=True)
    local.add_argument("--archive", type=Path, default=Path(DEFAULT_ARCHIVE))
    remote = sub.add_parser("run", help="Build and benchmark inside the benchctl queue")
    remote.add_argument("--archive", type=Path, default=Path(DEFAULT_ARCHIVE))
    remote.add_argument("--cc", default="gcc")
    remote.add_argument("--bench", choices=["pairing_compare", "group_compare"], default="pairing_compare")
    remote.add_argument("--test", action="store_true", help="Run crate tests and Criterion correctness smoke checks")
    remote.add_argument("criterion_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    {"snapshot": snapshot, "run": run}[args.action](args)


if __name__ == "__main__":
    main()

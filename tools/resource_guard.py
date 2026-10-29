#!/usr/bin/env python3
"""Bound one project job; account only named project roots without following links."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
GIB = 1024**3
NORMAL_DISK = 10_000_000_000
MAX_RSS = 2 * GIB
SCOPE_MEMORY_MAX = MAX_RSS - 128 * 1024**2  # Headroom for the outside supervisor.


def account(roots: list[Path] | None = None) -> dict:
    if roots is None:
        config = ROOT / ".local/resource-paths.json"
        roots = [Path(p) for p in json.loads(config.read_text())["roots"]] if config.exists() else [ROOT]
        data_root = os.environ.get("PAYBACK2_DATA_ROOT")
        if data_root and Path(data_root) not in roots:
            roots.append(Path(data_root))
    seen: set[tuple[int, int]] = set()
    entries = []
    for root in roots:
        allocated = apparent = inodes = 0
        paths = [root]
        if root.is_dir() and not root.is_symlink():
            for directory, dirs, files in os.walk(root, followlinks=False):
                paths.extend(Path(directory) / name for name in dirs + files)
        for path in paths:
            try:
                st = path.lstat()
            except FileNotFoundError:
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen:
                continue
            seen.add(key)
            allocated += st.st_blocks * 512
            apparent += st.st_size
            inodes += 1
        entries.append({"path": str(root), "allocated_bytes": allocated,
                        "apparent_bytes": apparent, "inodes": inodes})
    return {"roots": entries,
            "allocated_bytes": sum(x["allocated_bytes"] for x in entries),
            "apparent_bytes": sum(x["apparent_bytes"] for x in entries)}


def memory_available() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def cgroup_path() -> Path | None:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return Path("/sys/fs/cgroup") / line[3:].lstrip("/")
    return None


def process_snapshot() -> dict[int, tuple[int, int, int]]:
    result = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            result[int(path.name)] = (int(fields[1]), int(fields[19]),
                                      max(0, int(fields[21])) * os.sysconf("SC_PAGE_SIZE"))
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            continue
    return result


def owned_processes(snapshot: dict, root_pid: int, known: dict[int, int]) -> dict:
    owned = {pid: values for pid, values in snapshot.items()
             if pid == root_pid or known.get(pid) == values[1]}
    while True:
        additions = {pid: values for pid, values in snapshot.items()
                     if values[0] in owned and pid not in owned}
        if not additions:
            break
        owned.update(additions)
    known.update({pid: values[1] for pid, values in owned.items()})
    return owned


def stop_job(process: subprocess.Popen, known: dict[int, int]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        snapshot = process_snapshot()
        for pid, start in known.items():
            if pid in snapshot and snapshot[pid][1] == start:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    process.wait()


def monitor(args: argparse.Namespace) -> int:
    cpus = [int(x) for x in args.cpus.split(",")]
    os.sched_setaffinity(0, cpus)
    os.nice(max(0, 10 - os.getpriority(os.PRIO_PROCESS, 0)))
    env = dict(os.environ)
    env.update({"CMAKE_BUILD_PARALLEL_LEVEL": "2", "MAKEFLAGS": "-j2",
                "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1", "NUMEXPR_NUM_THREADS": "1",
                "npm_config_cache": str(ROOT / ".cache/npm"),
                "PIP_CACHE_DIR": str(ROOT / ".cache/pip"),
                "PYTHONPYCACHEPREFIX": str(ROOT / ".cache/pycache"),
                "XDG_CACHE_HOME": str(ROOT / ".cache/xdg"),
                "TMPDIR": str(ROOT / ".local/tmp")})
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("A command is required after --.")
    if shutil.which("ionice"):
        command = ["ionice", "-c", "2", "-n", "7", *command]
    group = cgroup_path() if args.mode == "cgroup" else None
    report = {"label": args.label, "cpus": cpus, "memory_enforcement": args.mode,
              "rss_limit_bytes": args.rss_limit, "timeout_seconds": args.timeout,
              "cgroup": str(group) if group else None, "status": "starting"}
    output = Path(args.report)
    output.write_text(json.dumps(report, indent=2) + "\n")
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    process = subprocess.Popen(command, env=env, start_new_session=True)
    known: dict[int, int] = {}
    peak_rss = 0
    failure = None
    high_reported = False
    try:
        while True:
            snapshot = process_snapshot()
            owned = owned_processes(snapshot, process.pid, known)
            rss = sum(v[2] for v in owned.values())
            peak_rss = max(peak_rss, rss)
            if rss > 1.5 * GIB and not high_reported:
                print("resource_guard: job crossed the 1.5 GiB soft threshold", file=sys.stderr)
                high_reported = True
            if rss >= args.rss_limit:
                failure = "aggregate RSS limit"
                break
            if time.monotonic() - started >= args.timeout:
                failure = "timeout"
                break
            if process.poll() is not None:
                # Do not leave detached children behind after the command ends.
                leftovers = {pid: v[1] for pid, v in owned.items() if pid != process.pid}
                if leftovers:
                    stop_job(process, leftovers)
                    failure = "command left running descendants"
                break
            time.sleep(0.1)
    except (KeyboardInterrupt, SystemExit):
        failure = "interrupted"
    finally:
        if failure:
            stop_job(process, known)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    report.update({"status": failure or "finished", "exit_code": process.returncode,
                   "elapsed_seconds": round(time.monotonic() - started, 4),
                   "sampled_peak_rss_bytes": peak_rss,
                   "child_cpu_seconds": round(after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime, 4)})
    if group:
        for name in ("memory.peak", "memory.events", "cpu.stat", "cpu.max", "memory.high", "memory.max", "memory.swap.max"):
            try:
                report[name] = (group / name).read_text().strip()
            except FileNotFoundError:
                pass
    report["disk_after"] = account()
    output.write_text(json.dumps(report, indent=2) + "\n")
    print("resource_guard: " + json.dumps({k: report[k] for k in
          ("label", "status", "exit_code", "memory_enforcement", "elapsed_seconds",
           "sampled_peak_rss_bytes", "child_cpu_seconds")}), file=sys.stderr)
    if failure:
        return 124 if failure == "timeout" else 125
    return process.returncode if process.returncode >= 0 else 128 - process.returncode


def run(args: argparse.Namespace) -> int:
    for path in (ROOT / ".local/tmp", ROOT / ".local/resources", ROOT / ".cache"):
        path.mkdir(parents=True, exist_ok=True)
    with (ROOT / ".local/job.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another project job holds the shared queue; finish it first.")
        budget = account()
        peak = max(budget["allocated_bytes"], budget["apparent_bytes"]) + args.reserve_bytes
        if peak >= NORMAL_DISK:
            raise SystemExit(f"Planned peak {peak} reaches the 10 GB normal target. Defer and document necessity/cleanup first.")
        if peak >= 8_000_000_000:
            print("resource_guard: review disposable project storage before substantial growth", file=sys.stderr)
        if memory_available() < 2 * GIB:
            raise SystemExit("Available system memory is below 2 GiB; defer this job.")
        cpus = sorted(os.sched_getaffinity(0))[:2]
        os.sched_setaffinity(0, cpus)
        identifier = uuid.uuid4().hex[:12]
        report = ROOT / ".local/resources" / f"{identifier}.json"
        common = [sys.executable, str(Path(__file__).resolve()), "_monitor",
                  "--timeout", str(args.timeout), "--label", args.label,
                  "--rss-limit", str(args.rss_limit), "--cpus", ",".join(map(str, cpus)),
                  "--report", str(report)]
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise SystemExit("A command is required after --.")
        # A failed job must never be automatically rerun outside its memory cap.
        # Opt into fallback explicitly on hosts where systemd scopes are absent.
        mode = "monitored-rss" if args.fallback else "cgroup"
        wrapped = [*common, "--mode", mode, "--", *command]
        if not args.fallback:
            if not shutil.which("systemd-run"):
                raise SystemExit("systemd-run unavailable; use --fallback for the documented RSS watchdog.")
            wrapped = ["systemd-run", "--scope", "--quiet", "--collect",
                       "--unit=payback2-job-" + identifier,
                       "--property=CPUQuota=200%", "--property=MemoryHigh=1610612736",
                       "--property=MemoryMax=" + str(SCOPE_MEMORY_MAX), "--property=MemorySwapMax=0",
                       "--property=AllowedCPUs=" + ",".join(map(str, cpus)),
                       "--property=TasksMax=128", *wrapped]
        else:
            print("resource_guard: fallback has sampled RSS enforcement, not a kernel memory cap", file=sys.stderr)
        result = subprocess.run(wrapped)
        if not report.exists():
            print("resource_guard: no job report; scope creation failed. No automatic retry.", file=sys.stderr)
        elif max(account()["allocated_bytes"], account()["apparent_bytes"]) >= NORMAL_DISK:
            print("resource_guard: storage target reached; stop growth and clean project disposables", file=sys.stderr)
            return 125
        return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("account")
    for name in ("run", "_monitor"):
        sub = commands.add_parser(name)
        sub.add_argument("--timeout", type=float, default=60)
        sub.add_argument("--label", default="job")
        sub.add_argument("--rss-limit", type=int, default=MAX_RSS)
        if name == "run":
            sub.add_argument("--reserve-bytes", type=int, default=0)
            sub.add_argument("--fallback", action="store_true")
        else:
            sub.add_argument("--cpus", required=True)
            sub.add_argument("--report", required=True)
            sub.add_argument("--mode", choices=("cgroup", "monitored-rss"), required=True)
        sub.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "account":
        print(json.dumps(account(), indent=2))
        return 0
    if not 0 < args.timeout <= 600 or not 0 < args.rss_limit <= MAX_RSS:
        parser.error("Timeout must be in (0, 600] seconds; RSS limit in (0, 2 GiB].")
    if args.action == "run" and args.reserve_bytes < 0:
        parser.error("Reserved growth cannot be negative.")
    return run(args) if args.action == "run" else monitor(args)


if __name__ == "__main__":
    sys.exit(main())

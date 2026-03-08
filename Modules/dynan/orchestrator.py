import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import docker

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from wise_config import CONFIG

IMAGE_TAG = CONFIG["dynan"]["image_tag"]
CONTAINER_NAME = CONFIG["dynan"]["container_name"]
STATS_POLL_INTERVAL = CONFIG["dynan"]["stats_poll_interval"]
EXECUTION_TIMEOUT = CONFIG["dynan"]["execution_timeout"]
CONTAINER_OUTPUT_DIR = CONFIG["dynan"]["container_output_dir"]
ARCHIVE_DIRNAME = CONFIG["dynan"]["archive_dirname"]


def parse_stats(raw):
    """Extract human-readable metrics from a Docker stats frame."""

    cpu_stats = raw.get("cpu_stats", {})
    precpu_stats = raw.get("precpu_stats", {})

    cpu_delta = (
        cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
    )
    system_delta = (
        cpu_stats.get("system_cpu_usage", 0)
        - precpu_stats.get("system_cpu_usage", 0)
    )
    num_cpus = cpu_stats.get("online_cpus", 1)
    cpu_pct = round((cpu_delta / system_delta) * num_cpus *
                    100, 2) if system_delta > 0 else 0.0

    mem_stats = raw.get("memory_stats", {})
    mem_usage = mem_stats.get("usage", 0)
    mem_limit = mem_stats.get("limit", 1)
    mem_pct = round((mem_usage / mem_limit) * 100, 2)

    rx_bytes = 0
    tx_bytes = 0
    networks = raw.get("networks", {})
    for iface in networks.values():
        rx_bytes += iface.get("rx_bytes", 0)
        tx_bytes += iface.get("tx_bytes", 0)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_pct": cpu_pct,
        "mem_bytes": mem_usage,
        "mem_pct": mem_pct,
        "net_rx_bytes": rx_bytes,
        "net_tx_bytes": tx_bytes,
    }


def build_image(project_dir):
    """Build the Docker image using docker CLI (streams output)."""
    print(f"[build] Building {IMAGE_TAG}...")
    subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "."],
        cwd=project_dir,
        check=True,
    )
    print("[build] Done")


def cleanup_container(client, name):
    """Remove any existing container with this name."""
    try:
        old = client.containers.get(name)
        old.remove(force=True)
    except docker.errors.NotFound:
        pass


def run_analysis(client, target_url, output_dir,
                 show_browser=False):
    """
    Create, start, poll stats, and wait for the analysis container.
    Returns the collected stats array.
    """

    cleanup_container(client, CONTAINER_NAME)

    env = {
        "TARGET_URL": target_url,
        "OUTPUT_DIR": "/output",
        "ANALYSIS_TIMEOUT_MS": str(CONFIG["dynan"]["run_analysis_timeout_ms"]),
        "ANALYSIS_OBSERVATION_MS": str(CONFIG["dynan"]["run_analysis_observation_time_ms"]),
    }
    extra_kwargs = {}

    parsed_url = urlparse(target_url)
    if parsed_url.hostname in ("localhost", "127.0.0.1"):
        print("[run] target URL refers to localhost; enabling host network mode")
        extra_kwargs["network_mode"] = "host"

    if show_browser:

        display = os.environ.get("DISPLAY", ":0")
        env["DISPLAY"] = display
        env["HEADLESS"] = "false"
        extra_kwargs.update(
            network_mode="host",
            ipc_mode="host",
            volumes={
                "/tmp/.X11-unix": {"bind": "/tmp/.X11-unix", "mode": "rw"},
                "/dev/shm": {"bind": "/dev/shm", "mode": "rw"},
            },
        )
        print(f"[run] X11 forwarding enabled (DISPLAY={display})")

    project_dir = os.path.dirname(os.path.abspath(__file__))
    extra_kwargs.setdefault("volumes", {}).update({
        os.path.join(project_dir, "run_analysis.js"): {"bind": "/app/run_analysis.js", "mode": "ro"},
        os.path.join(project_dir, "instrument.js"):   {"bind": "/app/instrument.js",   "mode": "ro"},
        os.path.join(project_dir, "analysis.js"):     {"bind": "/app/analysis.js",     "mode": "ro"},
    })

    print("[run] Starting analysis container...")
    container = client.containers.create(
        image=IMAGE_TAG,
        name=CONTAINER_NAME,
        environment=env,

        mem_limit="8g",
        nano_cpus=2_000_000_000,
        pids_limit=512,
        security_opt=["no-new-privileges"],

        shm_size="2g",

        cap_add=["NET_RAW", "NET_ADMIN"],
        detach=True,
        **extra_kwargs,
    )

    container.start()

    stats_log = []
    start_time = time.time()

    while True:
        elapsed = time.time() - start_time

        container.reload()
        status = container.status
        if status in ("exited", "dead"):
            result = container.wait()
            exit_code = result.get("StatusCode", -1)
            print(f"[run] Container exited with code {exit_code}")
            break

        if elapsed > EXECUTION_TIMEOUT:
            print(f"[run] Timeout ({EXECUTION_TIMEOUT}s) - killing container.")
            try:
                container.kill()
            except Exception:
                pass
            break

        try:
            raw = container.stats(stream=False)
            stats_log.append(parse_stats(raw))
        except Exception:
            pass

        time.sleep(STATS_POLL_INTERVAL)

    export_output(container, output_dir)

    try:
        container.remove(force=True)
    except Exception:
        pass

    return stats_log


def export_output(container, host_output_dir):
    """Copy /output from the container to the host output directory."""
    print(f"[export] Extracting output to {host_output_dir}...")

    os.makedirs(host_output_dir, exist_ok=True)

    try:

        cmd = ["docker", "cp",
               f"{container.id}:{CONTAINER_OUTPUT_DIR}/.", host_output_dir]

        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        print("[export] Done")

    except subprocess.CalledProcessError as e:
        print(
            f"[export] ERROR: docker cp failed: {e.stderr.decode('utf-8', errors='replace').strip()}")
    except Exception as e:
        print(f"[export] WARNING: Export failed: {e}")


def _safe_slug(value):
    """Create a filesystem-safe slug for archive naming."""
    if not value:
        return "unknown"
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", value)
    return slug.strip("._-") or "unknown"


def archive_output(host_output_dir, project_dir, target_url):
    """Create a compressed tar.gz archive containing all output artifacts."""

    os.makedirs(os.path.join(project_dir, ARCHIVE_DIRNAME), exist_ok=True)

    parsed = urlparse(target_url)
    target_id = _safe_slug(f"{parsed.netloc}{parsed.path}")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    base_name = os.path.join(
        project_dir,
        ARCHIVE_DIRNAME,
        f"artifacts_{target_id}_{timestamp}",
    )

    return shutil.make_archive(base_name=base_name, format="gztar", root_dir=host_output_dir)


def main():
    """Describe main."""
    parser = argparse.ArgumentParser(
        description="DYNAN — WASM Dynamic Analysis Orchestrator",
    )
    parser.add_argument(
        "target_url", help="URL of the website with WASM to analyze")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output directory (default: ./output)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Docker image build (use existing image)",
    )
    parser.add_argument(
        "--show-browser",
        action="store_true",
        help="Show browser on host via X11 forwarding (requires xhost +local:docker)",
    )
    args = parser.parse_args()

    parsed = urlparse(args.target_url)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] Invalid URL: {args.target_url}", file=sys.stderr)
        sys.exit(1)

    project_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(project_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[run] Target: {args.target_url}")
    print(f"[run] Output: {output_dir}")

    if not args.skip_build:
        build_image(project_dir)
    else:
        print("[build] Skipped")

    client = docker.from_env()
    stats_log = run_analysis(client, args.target_url, output_dir,
                             show_browser=args.show_browser)

    stats_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": args.target_url,
        "samples": len(stats_log),
        "stats": stats_log,
    }

    stats_path = os.path.join(output_dir, "docker_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats_report, f, indent=2)
    print(f"[stats] Written: {stats_path}")

    archive_path = archive_output(output_dir, project_dir, args.target_url)
    print(f"[archive] Written: {archive_path}")

    print(f"[run] Complete. Stats samples: {len(stats_log)}")


if __name__ == "__main__":
    main()

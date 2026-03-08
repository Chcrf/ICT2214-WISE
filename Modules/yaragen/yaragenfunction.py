import argparse
import docker
import os
from pathlib import Path
import platform

MALWARE_SAMPLES_DIR = Path(__file__).parent / "malware"
OUTPUT_DIR = Path(__file__).parent / "yara_rules"


def iter_samples(input_path):
    """Describe iter samples."""
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        return [
            f for f in input_path.iterdir()
            if f.is_file() and not f.name.startswith(".")
        ]
    return []


def run_yargen_analysis(input_path, output_dir, image):
    """Run yargen analysis."""
    client = docker.from_env()

    if not input_path.exists():
        print(f"[!] Error: Path does not exist: {input_path}")
        return False

    samples = iter_samples(input_path)
    if not samples:
        print(f"[!] Error: No files found in {input_path.absolute()}")
        return False

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Found {len(samples)} sample(s)")
    print(f"[*] Output Directory: {output_dir.absolute()}")

    user_mapping = None
    if platform.system() != "Windows":
        user_mapping = f"{os.getuid()}:{os.getgid()}"

    for index, sample in enumerate(samples, 1):
        output_filename = f"{sample.stem}.yara"

        print(
            f"\n[{index}/{len(samples)}] Processing: {sample.name} -> {output_filename}")

        try:
            container = client.containers.run(
                image=image,
                user=user_mapping,
                command=[
                    "-m", "/app/input",
                    "--excludegood",
                    "-o", f"/app/output/{output_filename}"
                ],
                volumes={
                    str(sample.absolute()): {'bind': f"/app/input/{sample.name}", 'mode': 'ro'},
                    str(output_dir.absolute()): {'bind': "/app/output", 'mode': 'rw'}
                },
                remove=True,
                detach=True
            )

            for line in container.logs(stream=True):
                log_line = line.decode("utf-8").strip()
                if "error" in log_line.lower() or "writing" in log_line.lower():
                    print(f"    [yarGen] {log_line}")

            print(f"    [+] Created: {output_filename}")

        except Exception as e:
            print(f"    [!] Error processing {sample.name}: {e}")

    print("\n[+] Analysis complete!")
    return True


def build_arg_parser():
    """Build arg parser."""
    parser = argparse.ArgumentParser(
        description="Generate YARA rules with yarGen for a file or directory of samples."
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="Path to a binary file or a directory of samples."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
        help=f"Directory to write YARA rules (default: {OUTPUT_DIR})."
    )
    parser.add_argument(
        "--image",
        default="yaragen:latest",
        help="Docker image to use (default: yaragen:latest)."
    )
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    run_yargen_analysis(args.input_path, args.output_dir, args.image)

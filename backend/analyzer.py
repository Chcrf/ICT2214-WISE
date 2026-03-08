try:
    from backend.database import (
        update_investigation_status,
        create_analysis_result,
        create_investigation,
        update_queue_stage,
        get_next_in_queue,
        add_to_queue,
        ANALYSIS_RESULTS_DIR,
        UPLOADS_DIR,
        save_dynamic_results,
        save_url_threat_intel,
        get_url_threat_intel,
        save_trace_viewer_payload,
    )
    from backend.threat_intel import query_scanners
except ImportError:
    from database import (
        update_investigation_status,
        create_analysis_result,
        create_investigation,
        update_queue_stage,
        get_next_in_queue,
        add_to_queue,
        ANALYSIS_RESULTS_DIR,
        UPLOADS_DIR,
        save_dynamic_results,
        save_url_threat_intel,
        get_url_threat_intel,
        save_trace_viewer_payload,
    )
    from threat_intel import query_scanners
import os
import sys
import subprocess
import re
import asyncio
import json
import base64
import io
import hashlib
import tempfile
import shutil
import glob
import tarfile
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULES_DIR = os.path.join(PROJECT_ROOT, "Modules")
for _path in (PROJECT_ROOT, MODULES_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from wise_config import CONFIG

try:
    from decompiler import decompile_wat, decompile_wat_with_artifacts
    AI_DECOMPILER_AVAILABLE = True
    print("[Analyzer] AI decompiler (WAT->C) loaded successfully")
except ImportError as e:
    AI_DECOMPILER_AVAILABLE = False
    decompile_wat = None
    decompile_wat_with_artifacts = None
    print(f"[Analyzer] AI decompiler not available: {e}")

executor = ThreadPoolExecutor(max_workers=2)

YARAGEN_SCRIPT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..",
                 "Modules", "yaragen", "yaragenfunction.py")
)
YARAGEN_IMAGE = CONFIG["analyzer"]["yaragen_image"]
YARAGEN_TIMEOUT = CONFIG["analyzer"]["yaragen_timeout"]
WASM_DECOMPILE_TIMEOUT = CONFIG["analyzer"]["wasm_decompile_timeout"]
ANALYSIS_WORKER_IDLE_SLEEP = CONFIG["analyzer"]["worker_idle_sleep_seconds"]
ANALYSIS_WORKER_ACTIVE_SLEEP = CONFIG["analyzer"]["worker_active_sleep_seconds"]


def run_yaragen(wasm_path):
    """Generate a YARA rule for a WASM file using yarGen (via docker).

    Returns: (yara_rule, error_message)
    """
    if not wasm_path or not os.path.exists(wasm_path):
        return None, "WASM file not found"
    if not os.path.exists(YARAGEN_SCRIPT):
        return None, f"yaragen script missing at {YARAGEN_SCRIPT}"

    output_dir = tempfile.mkdtemp(prefix="yaragen_")
    try:
        cmd = [
            sys.executable,
            YARAGEN_SCRIPT,
            wasm_path,
            "--output-dir",
            output_dir,
            "--image",
            YARAGEN_IMAGE,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=YARAGEN_TIMEOUT
        )
        print("[YARAGEN] stdout:", result.stdout)
        print("[YARAGEN] stderr:", result.stderr)
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            return None, err or "yaragen failed"

        output_file = os.path.join(output_dir, f"{Path(wasm_path).stem}.yara")
        if not os.path.exists(output_file):
            matches = list(Path(output_dir).glob("*.yara"))
            if matches:
                output_file = str(matches[0])
            else:
                return None, "yaragen did not produce output"

        with open(output_file, "r", encoding="utf-8", errors="replace") as f:
            yara_rule = f.read().strip()
        return yara_rule if yara_rule else None, None
    except subprocess.TimeoutExpired:
        return None, "yaragen timed out"
    except Exception as e:
        return None, str(e)
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def run_wasm_decompile(wasm_path):
    """
    Run wasm-decompile to get pseudo-C representation.

    Returns:
        Tuple of (decompiled_code, exports, imports)
    """
    try:
        result = subprocess.run(
            ["wasm-decompile", wasm_path],
            capture_output=True,
            text=True,
            timeout=WASM_DECOMPILE_TIMEOUT
        )

        if result.returncode != 0:
            return f"// Error: wasm-decompile failed\n// {result.stderr}", [], []

        decompiled = result.stdout

        exports = re.findall(r'export function (\w+)', decompiled)
        if not exports:
            exports = re.findall(r'function (\w+)', decompiled)

        imports = re.findall(r'import function (\w+)', decompiled)

        return decompiled, exports, imports

    except subprocess.TimeoutExpired:
        return "// Error: Decompilation timed out", [], []
    except FileNotFoundError:
        return "// Error: wasm-decompile not found. Install binaryen.", [], []
    except Exception as e:
        return f"// Error: {str(e)}", [], []


def _extract_threat_intel_urls(dynamic_payload, max_urls=25):
    """Extract unique http(s) URLs from dynamic analysis network data."""
    if not isinstance(dynamic_payload, dict):
        return []

    seen = set()
    urls = []

    meta = dynamic_payload.get("meta")
    if isinstance(meta, dict):
        target = meta.get("targetUrl")
        if isinstance(target, str) and target.lower().startswith(("http://", "https://")):
            seen.add(target)
            urls.append(target)

    docker = dynamic_payload.get("docker")
    if isinstance(docker, dict):
        target = docker.get("target_url")
        if isinstance(target, str) and target.lower().startswith(("http://", "https://")):
            if target not in seen:
                seen.add(target)
                urls.append(target)

    network = dynamic_payload.get("network")
    candidates = []
    if isinstance(network, dict):
        requests = network.get("requests")
        if isinstance(requests, list):
            candidates.extend(requests)
        by_run = network.get("byRun")
        if isinstance(by_run, list):
            for run in by_run:
                if not isinstance(run, dict):
                    continue
                run_requests = run.get("requests")
                if isinstance(run_requests, list):
                    candidates.extend(run_requests)
    elif isinstance(network, list):
        for run in network:
            if not isinstance(run, dict):
                continue
            run_requests = run.get("requests")
            if isinstance(run_requests, list):
                candidates.extend(run_requests)

    for item in candidates:
        if len(urls) >= max_urls:
            break
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        url = url.strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)

    return urls


def _load_dynamic_sidecar_for_wasm(wasm_path):
    """Load optional per-WASM dynamic-analysis sidecar JSON."""
    candidates = [
        f"{wasm_path}.dynamic.json",
        f"{os.path.splitext(wasm_path)[0]}.dynamic.json",
    ]
    for candidate in candidates:
        try:
            if os.path.exists(candidate):
                with open(candidate, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                if isinstance(payload, dict):
                    return payload
        except Exception as e:
            print(
                f"[Analyzer] Warning reading dynamic sidecar {candidate}: {e}")
    return None


async def run_ai_decompilation(
    wasm_path,
    investigation_id,
    dynamic_analysis_data=None,
):
    """
    Run the AI-enhanced decompilation using the LangGraph workflow.
    Pipeline: WASM -> WAT -> C (LLM)

    Returns:
        Tuple of (result_string, summary_string, function_map, security_report, success_bool)
    """

    if not AI_DECOMPILER_AVAILABLE or decompile_wat is None:
        return "// AI decompilation unavailable: Decompiler module not loaded", "", [], [], False

    try:

        loop = asyncio.get_event_loop()
        if decompile_wat_with_artifacts is not None:
            result, summary, function_name_map, security_report = await loop.run_in_executor(
                executor,
                lambda: decompile_wat_with_artifacts(
                    input_path=wasm_path,
                    dynamic_analysis_data=dynamic_analysis_data,
                )
            )
        else:
            result = await loop.run_in_executor(
                executor,
                lambda: decompile_wat(
                    input_path=wasm_path
                )
            )
            summary = ""
            function_name_map = []
            security_report = []

        if result.startswith("// Error:"):
            return result, summary, function_name_map, security_report, False

        return result, summary, function_name_map, security_report, True

    except Exception as e:
        error_msg = str(e).lower()

        if "api" in error_msg or "key" in error_msg or "auth" in error_msg:
            return f"// AI decompilation failed: API key not set or invalid\n// {str(e)}", "", [], [], False
        elif "token" in error_msg or "limit" in error_msg or "quota" in error_msg or "rate" in error_msg:
            return f"// AI decompilation failed: Token limit or rate limit exceeded\n// {str(e)}", "", [], [], False
        elif "timeout" in error_msg:
            return f"// AI decompilation failed: Request timed out\n// {str(e)}", "", [], [], False
        else:
            return f"// AI decompilation failed: {str(e)}", "", [], [], False


async def analyze_wasm_file(investigation_id, wasm_path):
    """
    Simplified WASM analysis pipeline.

    Steps:
    1. Run wasm-decompile (pseudo-C)
    2. Run AI-enhanced decompilation (slow, high-quality C)
    3. Store results in database
    """

    update_investigation_status(investigation_id, "analyzing")

    try:

        print(
            f"[Analyzer] Step 1: Running wasm-decompile for investigation {investigation_id}")
        wasm_decompile, exports, imports = await asyncio.to_thread(run_wasm_decompile, wasm_path)

        decompile_failed = wasm_decompile.startswith("// Error:")

        if decompile_failed:
            print(f"[Analyzer] Decompilation failed - invalid WASM file")

            create_analysis_result(
                investigation_id=investigation_id,
                wasm_decompile=wasm_decompile,
                analysis_summary=f"Analysis failed: Invalid or corrupted WASM file. Decompilation errors occurred.",
                functions=[],
                imports=[],
                exports=[],
                memory_usage="Unknown"
            )

            update_investigation_status(
                investigation_id, "failed", "invalid_file")

            return {
                "success": False,
                "investigation_id": investigation_id,
                "error": "Invalid or corrupted WASM file"
            }

        summary = "Decompilation outputs only."

        create_analysis_result(
            investigation_id=investigation_id,
            wasm_decompile=wasm_decompile,
            analysis_summary=summary,
            functions=[],
            imports=imports,
            exports=exports,
            memory_usage="Unknown"
        )

        print(f"[Analyzer] Step 2.5: Generating YARA rule")
        yara_rule, yara_error = await asyncio.to_thread(run_yaragen, wasm_path)
        if yara_rule:
            create_analysis_result(
                investigation_id=investigation_id,
                yara_rule=yara_rule
            )
        elif yara_error:
            print(f"[Analyzer] YARA generation skipped: {yara_error}")

        print(f"[Analyzer] Step 2: Running AI-enhanced decompilation")
        dynamic_analysis_data = _load_dynamic_sidecar_for_wasm(wasm_path)
        if dynamic_analysis_data:
            print(
                f"[Analyzer] Loaded dynamic sidecar for summary context: {wasm_path}")

        ai_decompile, ai_summary, function_name_map, security_report, ai_success = await run_ai_decompilation(
            wasm_path,
            investigation_id,
            dynamic_analysis_data=dynamic_analysis_data,
        )

        create_analysis_result(
            investigation_id=investigation_id,
            ai_decompile=ai_decompile,
            function_name_map=function_name_map,
        )

        if security_report:
            create_analysis_result(
                investigation_id=investigation_id,
                security_findings_json=json.dumps(security_report),
            )

        if ai_success and ai_summary:

            create_analysis_result(
                investigation_id=investigation_id,
                analysis_summary=ai_summary
            )
        elif security_report:

            create_analysis_result(
                investigation_id=investigation_id,
                analysis_summary=f"{len(security_report)} vulnerability findings identified."
            )

        if not ai_success:
            print(
                f"[Analyzer] AI decompilation failed for investigation {investigation_id}")

            ai_error_summary = f"{summary} ⚠️ AI-enhanced decompilation failed - results may be incomplete."
            create_analysis_result(
                investigation_id=investigation_id,
                analysis_summary=ai_error_summary
            )

            update_investigation_status(
                investigation_id, "completed", "ai_error")

            return {
                "success": True,
                "investigation_id": investigation_id,
                "partial_results": True,
                "ai_error": True
            }

        result = "completed"

        update_investigation_status(investigation_id, "completed", result)

        print(
            f"[Analyzer] Analysis complete for investigation {investigation_id}: {result}")

        return {
            "success": True,
            "investigation_id": investigation_id,
            "result": result
        }

    except Exception as e:
        print(
            f"[Analyzer] Error analyzing investigation {investigation_id}: {e}")
        update_investigation_status(investigation_id, "failed", "error")

        create_analysis_result(
            investigation_id=investigation_id,
            analysis_summary=f"Analysis failed: {str(e)}"
        )

        return {
            "success": False,
            "investigation_id": investigation_id,
            "error": str(e)
        }


async def process_queue_item():
    """Process the next item in the analysis queue."""
    item = get_next_in_queue()

    if not item:
        return None

    queue_id = item["id"]
    investigation_id = item["investigation_id"]
    file_path = item["file_path"]
    investigation_type = item.get("investigation_type")
    source = item.get("source")

    print(f"[Queue] Processing investigation {investigation_id}")

    update_queue_stage(queue_id, "processing")

    try:

        if investigation_type == "url":

            url = source
            try:
                project_dir = os.path.abspath(os.path.join(
                    os.path.dirname(__file__), "..", "Modules", "dynan"))

                temp_output = tempfile.mkdtemp(prefix="dynan_out_")

                cmd = [sys.executable, "orchestrator.py", url,
                       "--output", temp_output, "--skip-build"]
                proc = await asyncio.to_thread(
                    subprocess.run,
                    cmd,
                    cwd=project_dir,
                    capture_output=True,
                    text=True,
                )

                if proc.returncode != 0:
                    err = proc.stderr.strip() if proc.stderr else "Orchestrator failed"
                    update_investigation_status(
                        investigation_id, "failed", err)
                    update_queue_stage(queue_id, "failed", err)
                    return {"success": False, "error": err}

                archive_path = None
                for line in proc.stdout.splitlines():
                    m = re.match(r"\[archive\] Written: (.+)$", line)
                    if m:
                        archive_path = m.group(1).strip()
                        break

                try:
                    shutil.rmtree(temp_output)
                except Exception:
                    pass

                if archive_path is None or not os.path.exists(archive_path):

                    archive_path = None

                archive_dir = None

                if archive_path and os.path.exists(archive_path):
                    try:
                        archive_dir = tempfile.mkdtemp(prefix="dynan_arch_")
                        with tarfile.open(archive_path, "r:*") as tf:
                            tf.extractall(path=archive_dir)
                    except Exception as e:
                        print(
                            f"[Analyzer] Failed to unpack specified archive {archive_path}: {e}")
                        archive_dir = None

                if archive_dir is None:

                    tars = glob.glob(os.path.join(
                        project_dir, "archives", "*.tar*"))
                    if tars:
                        def _extract_ts(path):
                            """Describe  extract ts."""
                            basename = os.path.basename(path)
                            m = re.search(r"_(\d{8}T\d{6}Z)\.tar", basename)
                            if m:
                                try:
                                    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")
                                except Exception:
                                    pass
                            return datetime.fromtimestamp(os.path.getmtime(path))
                        tars.sort(key=_extract_ts)
                        latest = tars[-1]
                        try:
                            archive_dir = tempfile.mkdtemp(
                                prefix="dynan_arch_")
                            with tarfile.open(latest, "r:*") as tf:
                                tf.extractall(path=archive_dir)
                        except Exception as e:
                            print(
                                f"[Analyzer] Failed to unpack archive {latest}: {e}")
                            archive_dir = None

                artifact_base = archive_dir if archive_dir else os.path.join(
                    project_dir, "output")
                if not os.path.exists(artifact_base):
                    msg = "Orchestrator produced no usable artifacts"
                    update_investigation_status(
                        investigation_id, "failed", msg)
                    update_queue_stage(queue_id, "failed", msg)
                    return {"success": False, "error": msg}

                extracted_files = os.listdir(artifact_base)
                wasm_files = [os.path.join(artifact_base, f)
                              for f in extracted_files if f.endswith(".wasm")]

                if not wasm_files:
                    msg = "No wasm files found in archive artifacts"
                    update_investigation_status(
                        investigation_id, "failed", msg)
                    update_queue_stage(queue_id, "failed", msg)
                    return {"success": False, "error": msg}

                analysis_report = None

                try:
                    dyn = {}

                    dyn_meta = {
                        "targetUrl": source or "",
                        "generatedAt": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
                    }
                    dyn["meta"] = dyn_meta

                    def _load_json_file(path):
                        """Describe  load json file."""
                        try:
                            with open(path, 'r') as f:
                                return json.load(f)
                        except Exception:
                            return None

                    stats = _load_json_file(os.path.join(
                        artifact_base, "docker_stats.json"))
                    analysis = _load_json_file(os.path.join(
                        artifact_base, "analysis_report.json"))
                    network = _load_json_file(os.path.join(
                        artifact_base, "network_report.json"))

                    target_url = stats["target_url"] if isinstance(
                        stats, dict) and "target_url" in stats else None

                    if isinstance(stats, dict) and isinstance(stats.get("stats"), list):
                        stats = stats["stats"]

                    if isinstance(network, list):
                        merged_requests = []
                        merged_responses = []
                        by_run = []
                        for run in network:
                            if isinstance(run, dict):
                                run_requests = run.get("requests", []) if isinstance(
                                    run.get("requests"), list) else []
                                run_responses = run.get("responses", []) if isinstance(
                                    run.get("responses"), list) else []
                                merged_requests.extend(run_requests)
                                merged_responses.extend(run_responses)
                                by_run.append({
                                    "runIndex": run.get("runIndex"),
                                    "wasmFileName": run.get("wasmFileName"),
                                    "targetWasmUrl": run.get("targetWasmUrl"),
                                    "requests": run_requests,
                                    "responses": run_responses,
                                })
                        network = {"requests": merged_requests,
                                   "responses": merged_responses, "byRun": by_run}
                    elif not isinstance(network, dict):

                        network = {"requests": [],
                                   "responses": [], "byRun": []}
                    else:
                        network.setdefault("requests", [])
                        network.setdefault("responses", [])
                        network.setdefault("byRun", [])

                    if archive_dir:
                        for fname in os.listdir(archive_dir):
                            if fname.startswith("trace_run_") and fname.endswith(".zip"):
                                zp = os.path.join(archive_dir, fname)
                                try:
                                    with zipfile.ZipFile(zp) as zz:
                                        for zmember in zz.namelist():
                                            if zmember.endswith("docker_stats.json") and stats is None:
                                                stats = json.loads(
                                                    zz.read(zmember))
                                            if zmember.endswith("analysis_report.json") and analysis is None:
                                                analysis = json.loads(
                                                    zz.read(zmember))
                                            if zmember.endswith("network_report.json") and network is None:
                                                network = json.loads(
                                                    zz.read(zmember))
                                except Exception:
                                    pass

                    analysis_report = analysis if isinstance(
                        analysis, dict) else None
                    dyn["docker"] = {
                        "stats": stats if isinstance(stats, list) else [],
                        "target_url": target_url,
                    }
                    dyn["runs"] = analysis_report.get(
                        "runs", []) if isinstance(analysis_report, dict) else []
                    dyn["wasm"] = analysis_report.get(
                        "wasm", {}) if isinstance(analysis_report, dict) else {}

                    dyn["network"] = network if network is not None else []

                    artifacts = []
                    trace_viewer_payload = {
                        "status": "missing",
                        "message": "trace-viewer file does not exist",
                    }
                    for fname in sorted(os.listdir(artifact_base)):
                        fpath = os.path.join(artifact_base, fname)
                        if not os.path.isfile(fpath):
                            continue
                        try:
                            with open(fpath, "rb") as fb:
                                raw = fb.read()
                            encoded = base64.b64encode(raw).decode("ascii")

                            if fname == "trace_run_1.zip":
                                trace_viewer_dir = os.path.join(
                                    ANALYSIS_RESULTS_DIR, f"trace_viewer_{investigation_id}")
                                try:
                                    if os.path.exists(trace_viewer_dir):
                                        shutil.rmtree(trace_viewer_dir)
                                    os.makedirs(trace_viewer_dir,
                                                exist_ok=True)
                                    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                                        for member in zf.infolist():
                                            member_name = member.filename
                                            if member.is_dir():
                                                continue
                                            if member_name.startswith("/") or ".." in member_name.split("/"):
                                                continue
                                            out_path = os.path.abspath(
                                                os.path.join(trace_viewer_dir, member_name))
                                            if not out_path.startswith(os.path.abspath(trace_viewer_dir) + os.sep):
                                                continue
                                            os.makedirs(os.path.dirname(
                                                out_path), exist_ok=True)
                                            with zf.open(member) as src, open(out_path, "wb") as dst:
                                                dst.write(src.read())
                                except Exception:
                                    pass
                                trace_viewer_payload = {
                                    "status": "available",
                                    "fileName": fname,
                                    "fileSize": len(raw),
                                    "mimeType": "application/zip",
                                    "fileData": encoded,
                                    "traceUrl": f"/api/trace-viewer/{investigation_id}/manifest.traces.dir",
                                }

                            artifacts.append({
                                "fileName": fname,
                                "fileSize": len(raw),
                                "fileData": encoded,
                            })
                        except Exception:
                            continue
                    dyn["artifacts"] = artifacts

                    save_dynamic_results(investigation_id, dyn)
                    save_trace_viewer_payload(
                        investigation_id, trace_viewer_payload)
                    cached_threat = get_url_threat_intel(investigation_id)
                    if not cached_threat:
                        urls = _extract_threat_intel_urls(dyn)
                        if urls:
                            results = []
                            for url in urls:
                                scanners = await query_scanners(url)
                                results.append(
                                    {"target_url": url, "scanners": scanners})
                            save_url_threat_intel(investigation_id, results)
                except Exception as e:
                    print(f"[Analyzer] Warning saving dynamic results: {e}")

                run_map: Dict[str, List[Dict]] = {}
                if isinstance(analysis_report, dict):
                    for run in analysis_report.get("runs", []):
                        if isinstance(run, dict):
                            name = (run.get("wasmFileName") or "").strip()
                            if name:
                                run_map.setdefault(name, []).append(run)

                url_upload_dir = os.path.join(
                    UPLOADS_DIR, "url", str(investigation_id))
                os.makedirs(url_upload_dir, exist_ok=True)

                created_children = []
                for wasm in wasm_files:
                    filename = os.path.basename(wasm)
                    matched_run = None
                    if filename in run_map and run_map[filename]:
                        matched_run = run_map[filename].pop(0)
                    else:
                        for key, runs in run_map.items():
                            if filename.endswith(f"_{key}") and runs:
                                matched_run = runs.pop(0)
                                break

                    target_url = matched_run.get("targetWasmUrl") if isinstance(
                        matched_run, dict) else None
                    display_name = matched_run.get("wasmFileName") if isinstance(
                        matched_run, dict) and matched_run.get("wasmFileName") else filename

                    try:
                        with open(wasm, "rb") as f:
                            data = f.read()
                    except Exception as e:
                        print(f"[Analyzer] Failed reading wasm {wasm}: {e}")
                        continue

                    sha256_hash = hashlib.sha256(data).hexdigest()
                    md5_hash = hashlib.md5(data).hexdigest()
                    sha1_hash = hashlib.sha1(data).hexdigest()
                    file_size = len(data)

                    dest_path = os.path.join(
                        url_upload_dir, f"{sha256_hash}.wasm")
                    if not os.path.exists(dest_path):
                        try:
                            with open(dest_path, "wb") as f:
                                f.write(data)
                        except Exception as e:
                            print(
                                f"[Analyzer] Failed writing wasm to {dest_path}: {e}")
                            continue

                    dynamic_sidecar = {
                        "target_url": target_url or url,
                        "runs": [matched_run] if isinstance(matched_run, dict) else [],
                        "docker_stats": stats if isinstance(stats, list) else [],
                        "network_report": network if isinstance(network, (list, dict)) else [],
                    }
                    if isinstance(analysis_report, dict):
                        dynamic_sidecar["analysis_report"] = {
                            "wasm": analysis_report.get("wasm", {}),
                            "runs": [matched_run] if isinstance(matched_run, dict) else [],
                        }
                    sidecar_path = f"{dest_path}.dynamic.json"
                    try:
                        with open(sidecar_path, "w", encoding="utf-8") as sidecar_file:
                            json.dump(dynamic_sidecar, sidecar_file,
                                      indent=2, ensure_ascii=False)
                    except Exception as e:
                        print(
                            f"[Analyzer] Warning writing dynamic sidecar {sidecar_path}: {e}")

                    child_id = create_investigation(
                        sha256_hash=sha256_hash,
                        sample_name=display_name or filename,
                        md5_hash=md5_hash,
                        sha1_hash=sha1_hash,
                        file_size=file_size,
                        file_type="application/wasm",
                        file_path=dest_path,
                        investigation_type="file",
                        source=target_url,
                        parent_investigation_id=investigation_id,
                    )
                    if child_id:
                        add_to_queue(child_id, priority=1)
                        created_children.append(child_id)

                update_investigation_status(
                    investigation_id, "completed", "children_queued")

                update_queue_stage(queue_id, "completed")
                return {"success": True, "investigation_id": investigation_id, "wasm_files": [os.path.basename(p) for p in wasm_files], "children": created_children}

            except Exception as e:
                err = str(e)
                update_investigation_status(investigation_id, "failed", err)
                update_queue_stage(queue_id, "failed", err)
                return {"success": False, "error": err}

        result = await analyze_wasm_file(investigation_id, file_path)

        if result["success"]:
            update_queue_stage(queue_id, "completed")
        else:

            update_investigation_status(investigation_id, "failed", "error")
            update_queue_stage(queue_id, "failed",
                               result.get("error", "Unknown error"))

        return result

    except Exception as e:

        error_msg = str(e)
        print(
            f"[Queue] Unexpected error processing investigation {investigation_id}: {error_msg}")

        try:
            update_investigation_status(investigation_id, "failed", "error")
        except:
            pass

        update_queue_stage(queue_id, "failed", error_msg)
        return {"success": False, "error": error_msg}


async def run_analysis_worker():
    """Background worker that processes the analysis queue."""
    while True:
        result = await process_queue_item()
        if result is None:

            await asyncio.sleep(ANALYSIS_WORKER_IDLE_SLEEP)
        else:

            await asyncio.sleep(ANALYSIS_WORKER_ACTIVE_SLEEP)

import sys
import os
import asyncio
import hashlib
from contextlib import asynccontextmanager
from typing import List, Union

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from wise_config import CONFIG
try:
    from backend.threat_intel import query_scanners
except ImportError:
    from threat_intel import query_scanners
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shutil
import mimetypes
import base64
import io
import zipfile
from pathlib import Path

try:
    import uvicorn
except ImportError:
    uvicorn = None

try:
    from backend.database import (
        init_database,
        create_investigation,
        get_investigation_by_hash,
        get_investigation_by_id,
        get_analysis_by_id,
        get_all_investigations,
        get_investigations_count,
        get_analysis_by_hash,
        add_to_queue,
        get_queue_status,
        get_children_for_parent,
        delete_investigation,
        get_dynamic_results,
        get_url_threat_intel,
        save_url_threat_intel,
        get_trace_viewer_payload,
        ANALYSIS_RESULTS_DIR,
        UPLOADS_DIR
    )
    from backend.analyzer import run_analysis_worker
except ImportError:
    from database import (
        init_database,
        create_investigation,
        get_investigation_by_hash,
        get_investigation_by_id,
        get_analysis_by_id,
        get_all_investigations,
        get_investigations_count,
        get_analysis_by_hash,
        add_to_queue,
        get_queue_status,
        get_children_for_parent,
        delete_investigation,
        get_dynamic_results,
        get_url_threat_intel,
        save_url_threat_intel,
        get_trace_viewer_payload,
        ANALYSIS_RESULTS_DIR,
        UPLOADS_DIR
    )
    from analyzer import run_analysis_worker


analyze_url_dynamic = None
def is_url_analysis_available(): return False


analysis_worker_task = None


@asynccontextmanager
async def lifespan(app):
    """Startup and shutdown events."""
    global analysis_worker_task

    print("[WISE] Initializing database...")
    init_database()

    print("[WISE] Starting analysis worker...")
    analysis_worker_task = asyncio.create_task(run_analysis_worker())

    yield

    print("[WISE] Shutting down analysis worker...")
    if analysis_worker_task:
        analysis_worker_task.cancel()
        try:
            await analysis_worker_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title="WISE API",
    description="WebAssembly Intelligence & Security Engine",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG["backend"]["cors_origins"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLAnalysis(BaseModel):
    url: str


class ThreatReportRequest(BaseModel):
    urls: List[str]


def format_file_size(size_bytes):
    """Format file size to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


@app.post("/api/analyze/file")
async def analyze_file(file=File(...)):
    """
    Upload and analyze a WASM file.

    1. Calculates file hashes
    2. Stores file and creates investigation record
    3. Queues file for analysis
    4. Returns immediately with file info (analysis runs in background)
    """
    try:
        contents = await file.read()
        file_name = file.filename or "unknown.wasm"

        if len(contents) > 50 * 1024 * 1024:
            raise HTTPException(
                status_code=413, detail="File too large (max 50MB)")

        is_wasm = contents[:4] == b'\x00asm' or file_name.endswith('.wasm')
        if not is_wasm:
            raise HTTPException(
                status_code=400, detail="Invalid file type. Expected .wasm")

        md5_hash = hashlib.md5(contents).hexdigest()
        sha1_hash = hashlib.sha1(contents).hexdigest()
        sha256_hash = hashlib.sha256(contents).hexdigest()

        file_size = len(contents)

        existing = get_investigation_by_hash(sha256_hash)
        if existing:
            return {
                "success": True,
                "message": "File already analyzed",
                "existing": True,
                "investigation_id": existing["id"],
                "file_info": {
                    "name": file_name,
                    "size": file_size,
                    "size_formatted": format_file_size(file_size),
                    "type": file.content_type,
                },
                "hashes": {
                    "md5": md5_hash,
                    "sha1": sha1_hash,
                    "sha256": sha256_hash,
                },
                "status": existing["status"],
                "result": existing["result"]
            }

        file_path = os.path.join(UPLOADS_DIR, f"{sha256_hash}.wasm")
        with open(file_path, "wb") as f:
            f.write(contents)

        investigation_id = create_investigation(
            sha256_hash=sha256_hash,
            sample_name=file_name,
            md5_hash=md5_hash,
            sha1_hash=sha1_hash,
            file_size=file_size,
            file_type=file.content_type,
            file_path=file_path
        )

        add_to_queue(investigation_id, priority=1)

        return {
            "success": True,
            "message": "File uploaded and queued for analysis",
            "existing": False,
            "investigation_id": investigation_id,
            "file_info": {
                "name": file_name,
                "size": file_size,
                "size_formatted": format_file_size(file_size),
                "type": file.content_type,
            },
            "hashes": {
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
            },
            "analysis": {
                "status": "queued",
                "message": "Analysis will begin shortly",
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/url", status_code=202)
async def analyze_url(data: URLAnalysis):
    """
    Enqueue a URL dynamic analysis job.

    This creates an `investigation` record of type `url`, enqueues it
    for background processing by the existing analysis worker, and
    immediately returns an `investigation_id` (job id).
    """
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:

        url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()

        investigation_id = create_investigation(
            sha256_hash=url_hash,
            sample_name=url,
            md5_hash=None,
            sha1_hash=None,
            file_size=None,
            file_type=None,
            file_path=None,
            investigation_type='url',
            source=url,
        )

        if investigation_id is None:
            raise HTTPException(
                status_code=500, detail="Failed to create investigation record")

        add_to_queue(investigation_id, priority=1)

        return {
            "success": True,
            "investigation_id": investigation_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigations")
async def get_investigations(page=1, page_size=10):
    """Retrieve paginated list of investigations."""
    try:
        investigations = get_all_investigations(page, page_size)
        total = get_investigations_count()

        return {
            "success": True,
            "page": page,
            "page_size": page_size,
            "total": total,
            "investigations": investigations,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analysis/{sample_hash}")
async def get_analysis(sample_hash):
    """Retrieve analysis data for a given sample hash or investigation id."""
    try:
        analysis_data = None
        if sample_hash.isdigit():
            try:
                analysis_data = get_analysis_by_id(int(sample_hash))
            except Exception:
                analysis_data = None

        if analysis_data is None:
            analysis_data = get_analysis_by_hash(sample_hash)

        if not analysis_data:
            raise HTTPException(
                status_code=404,
                detail="Analysis data not found for the given identifier"
            )

        return {
            "success": True,
            "analysis_data": analysis_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/queue/status")
async def get_processing_queue_status():
    """Get current processing queue status."""
    try:
        status = get_queue_status()

        current_process = None
        if status["current"]:
            current_process = {
                "name": status["current"]["sample_name"],
                "stages": [
                    {"id": 1, "name": "wasm-decompile", "status": "done"},
                    {"id": 2, "name": "AI Decompile", "status": "in-progress"},
                ]
            }

        queue = [{"name": item["sample_name"]} for item in status["queue"]]
        completed = [{"name": item["sample_name"]}
                     for item in status["completed"]]
        failed = [{"name": item["sample_name"]}
                  for item in status.get("failed", [])]

        return {
            "success": True,
            "currentProcess": current_process,
            "queue": queue,
            "completed": completed,
            "failed": failed
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reanalyze/{sample_hash}")
async def reanalyze_sample(sample_hash):
    """Re-run analysis on an existing sample."""
    try:
        investigation = get_investigation_by_hash(sample_hash)

        if not investigation:
            raise HTTPException(status_code=404, detail="Sample not found")

        if investigation.get("investigation_type") == "url" and not investigation.get("parent_investigation_id"):
            parent_id = investigation["id"]

            children = get_children_for_parent(parent_id)
            for child in children:
                child_id = child["id"]
                child_row = get_investigation_by_id(child_id) or {}
                child_path = child_row.get("file_path")
                if child_path and os.path.exists(child_path):
                    try:
                        os.remove(child_path)
                    except Exception:
                        pass

                analysis_db_path = os.path.join(os.path.dirname(
                    __file__), "analysis_results", f"analysis_{child_id}.db")
                if os.path.exists(analysis_db_path):
                    try:
                        os.remove(analysis_db_path)
                    except Exception:
                        pass

                fn_map_path = os.path.join(os.path.dirname(
                    __file__), "analysis_results", f"function_map_{child_id}.json")
                if os.path.exists(fn_map_path):
                    try:
                        os.remove(fn_map_path)
                    except Exception:
                        pass

                delete_investigation(child_id)

            url_upload_dir = os.path.join(UPLOADS_DIR, "url", str(parent_id))
            if os.path.exists(url_upload_dir):
                try:
                    shutil.rmtree(url_upload_dir)
                except Exception:
                    pass

            add_to_queue(parent_id, priority=2)
            return {
                "success": True,
                "message": "URL re-analysis queued",
                "investigation_id": parent_id,
            }

        if not investigation.get("file_path") or not os.path.exists(investigation["file_path"]):
            raise HTTPException(
                status_code=404, detail="Sample file not found (sample lost)")

        add_to_queue(investigation["id"], priority=2)

        return {
            "success": True,
            "message": "Re-analysis queued",
            "investigation_id": investigation["id"]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-report/{investigation_id}")
async def get_threat_report(investigation_id: int):
    """Get threat report."""
    cached = get_url_threat_intel(investigation_id)
    if cached:
        return cached
    raise HTTPException(status_code=404, detail="No cached threat intel")


@app.post("/api/threat-report/{investigation_id}")
async def generate_threat_report(
    investigation_id: int,
    data: Union[ThreatReportRequest, List[str]]
):
    """Describe generate threat report."""
    urls = data.urls if isinstance(data, ThreatReportRequest) else data
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is required")

    inv = get_investigation_by_id(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    finalResult = []
    for url in urls:
        results = await query_scanners(url)
        finalResult.append({"target_url": url, "scanners": results})

    save_url_threat_intel(investigation_id, finalResult)
    return finalResult


@app.get("/api/trace-viewer/{investigation_id}")
async def get_trace_viewer(investigation_id: int):
    """Get trace viewer."""
    payload = get_trace_viewer_payload(investigation_id)
    if payload is not None:
        return payload

    inv = get_investigation_by_id(investigation_id)
    parent_id = inv.get("parent_investigation_id") if inv else None
    if parent_id:
        parent_dynamic = get_dynamic_results(parent_id) or {}
        runs = parent_dynamic.get("runs") if isinstance(
            parent_dynamic, dict) else []
        artifacts = parent_dynamic.get("artifacts") if isinstance(
            parent_dynamic, dict) else []

        target_url = (inv.get("source") or "").strip()
        target_name = (inv.get("sample_name") or "").strip()
        run_index = None

        if isinstance(runs, list):
            for idx, run in enumerate(runs, start=1):
                if not isinstance(run, dict):
                    continue
                run_url = (run.get("targetWasmUrl") or "").strip()
                run_name = (run.get("wasmFileName") or "").strip()
                name_match = False
                if target_name and run_name:
                    tn = os.path.basename(target_name).lower()
                    rn = os.path.basename(run_name).lower()
                    name_match = rn == tn or rn.endswith(
                        tn) or tn.endswith(rn) or rn in tn or tn in rn
                url_match = bool(target_url and run_url and (
                    run_url == target_url or run_url.endswith(target_url) or target_url.endswith(run_url)))
                if url_match or name_match:
                    run_index = idx
                    break

        trace_file = f"trace_run_{run_index}.zip" if run_index else None
        trace_artifact = None
        if trace_file and isinstance(artifacts, list):
            for item in artifacts:
                if isinstance(item, dict) and item.get("fileName") == trace_file:
                    trace_artifact = item
                    break

        if trace_artifact and isinstance(trace_artifact.get("fileData"), str):
            try:
                raw = base64.b64decode(
                    trace_artifact["fileData"], validate=False)
                trace_viewer_dir = _trace_viewer_dir(investigation_id)
                if trace_viewer_dir.exists():
                    shutil.rmtree(trace_viewer_dir)
                trace_viewer_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        member_name = member.filename
                        if member_name.startswith("/") or ".." in member_name.split("/"):
                            continue
                        out_path = (trace_viewer_dir / member_name).resolve()
                        if not str(out_path).startswith(str(trace_viewer_dir.resolve()) + os.sep):
                            continue
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, open(out_path, "wb") as dst:
                            dst.write(src.read())
                return {
                    "status": "available",
                    "fileName": trace_artifact.get("fileName"),
                    "fileSize": trace_artifact.get("fileSize"),
                    "mimeType": "application/zip",
                    "fileData": trace_artifact.get("fileData"),
                    "traceUrl": f"/api/trace-viewer/{investigation_id}/manifest.traces.dir",
                }
            except Exception:
                pass
    return {
        "status": "missing",
        "message": "trace-viewer file does not exist",
    }


def _trace_viewer_dir(investigation_id):
    """Describe  trace viewer dir."""
    return Path(ANALYSIS_RESULTS_DIR) / f"trace_viewer_{investigation_id}"


@app.get("/api/trace-viewer/{investigation_id}/manifest.traces.dir")
async def get_trace_viewer_manifest(investigation_id: int, request: Request):
    """Get trace viewer manifest."""
    base = _trace_viewer_dir(investigation_id)
    if not base.exists() or not base.is_dir():
        raise HTTPException(
            status_code=404, detail="Trace viewer files not found")

    base_url = str(request.base_url).rstrip("/")
    entries = []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        entries.append({
            "name": rel,
            "path": f"{base_url}/api/trace-viewer/{investigation_id}/files/{rel}",
        })
    return {"entries": entries}


@app.get("/api/trace-viewer/{investigation_id}/files/{entry_path:path}")
async def get_trace_viewer_file(investigation_id: int, entry_path: str):
    """Get trace viewer file."""
    base = _trace_viewer_dir(investigation_id).resolve()
    candidate = (base / entry_path).resolve()
    if not str(candidate).startswith(str(base) + os.sep):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    media_type, _ = mimetypes.guess_type(str(candidate))
    return FileResponse(str(candidate), media_type=media_type or "application/octet-stream")

if __name__ == "__main__":
    if uvicorn is None:
        raise RuntimeError("uvicorn is required to run the API server")
    uvicorn.run(
        "backend.main:app",
        host=CONFIG["backend"]["host"],
        port=CONFIG["backend"]["port"],
        reload=CONFIG["backend"]["reload"],
    )

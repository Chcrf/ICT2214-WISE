import { Check, Download } from "lucide-react";
import { useState } from "react";
import "./Artifacts.css"

// MIME type map 
const MIME_MAP = {
  log: { mime: "text/plain", binary: false },
  json: { mime: "application/json", binary: false },
  pcap: { mime: "application/vnd.tcpdump.pcap", binary: true },
  pcapng: { mime: "application/vnd.tcpdump.pcap", binary: true },
  wasm: { mime: "application/wasm", binary: true },
}

function getFileMeta(fileName) {
  const ext = fileName.split(".").pop().toLowerCase();
  return MIME_MAP[ext] ?? { mime: "application/octet-stream", binary: true };
}

function toBlob(fileName, fileData) {
  const meta = getFileMeta(fileName);

  // Backend artifacts are stored as base64 strings for both text and binary files.
  // Decode first; fallback to raw content only when the value isn't valid base64.
  try {
    const bytes = Uint8Array.from(atob(fileData), c => c.charCodeAt(0));
    return new Blob([bytes], { type: meta.mime });
  } catch {
    return new Blob([fileData], { type: meta.mime });
  }
}

function downloadFile(fileName, fileData) {
  const blob = toBlob(fileName, fileData);
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: fileName });
  a.click();
  URL.revokeObjectURL(url);
}

function downloadAll(files) {
  files.forEach((f, i) => setTimeout(() => downloadFile(f.fileName, f.fileData), i * 200));
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${u[i]}`;
}

const totalBytes = files => files.reduce((s, f) => s + (f.fileSize ?? 0), 0);

// Components
function FileRow({ file, index }) {
  const [saved, setSaved] = useState(false);
  const meta = getFileMeta(file.fileName);

  function handleSave(e) {
    downloadFile(file.fileName, file.fileData);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="dl-row">
      <div className="dl-row-top">
        <span className="dl-line-num">{String(index + 1).padStart(2, "0")}</span>

        <div className="dl-info">
          <div className="dl-filename">{file.fileName}</div>
          <div className="dl-meta">
            <span className="dl-filesize">{formatBytes(file.fileSize)}</span>
            <span className="dl-sep" />
            <span className="dl-mimetype">{meta.mime}</span>
          </div>
        </div>

        <div className="dl-actions">
          <button className={`dl-btn-save${saved ? " saved" : ""}`} onClick={handleSave}>
            {saved
              ? <><span className="dl-check"><Check size={13} /></span> Saved</>
              : <><Download size={13} />Save</>
            }
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Downloads({ files }) {
  const [allSaved, setAllSaved] = useState(false);

  if (!files || files.length === 0) {
    return (
      <div className="empty-data">
        No artifacts available
      </div>
    )
  }

  function handleDownloadAll() {
    downloadAll(files);
    setAllSaved(true);
    setTimeout(() => setAllSaved(false), 2500);
  }

  return (
    <div className="dl-container">
      <div className="dl-header">
        <div className="dl-header-right">
          <span className="dl-header-meta">
            {files.length} FILE{files.length !== 1 ? "S" : ""} · {formatBytes(totalBytes(files))}
          </span>
        </div>
        <button
          className={`dl-btn-all${allSaved ? " saved" : ""}`}
          onClick={handleDownloadAll}
        >
          {allSaved ? (
            <span className="dl-btn-all-text">
              <Check size={15} />
              All Saved
            </span>
          ) : (
            <span className="dl-btn-all-text">
              <Download size={15} />
              Download All
            </span>
          )}
        </button>
      </div>

      <div className="dl-list">
        {files.map((file, i) => (
          <FileRow key={file.fileName + i} file={file} index={i} />
        ))}
      </div>

    </div>
  );
}

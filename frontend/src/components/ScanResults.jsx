import { useState, useRef } from "react";
import { createPortal } from "react-dom";
import './ScanResults.css';

// Helpers
function pillStatus(scanner) {
  if (!scanner.success) {
    if (scanner.error?.toLowerCase().includes("key")) return "no_api_key";
    return "failed";
  }
  return scanner.verdict ?? "unknown";
}

const SCANNER_META = {
  virustotal: { label: "VirusTotal", dotColor: "#22c55e" },
  otx: { label: "AlienVault OTX", dotColor: "#3b82f6" },
  opencti: { label: "OpenCTI", dotColor: "#ef4444" },
};

const VERDICT_COLOR = {
  malicious: "#fca5a5",
  suspicious: "#fde68a",
  clean: "#bbf7d0",
  no_api_key: "#c4b5fd",
  failed: "#94a3b8",
  unknown: "#e2e8f0",
};

function verdictLabel(status) {
  return { malicious: "Malicious", suspicious: "Suspicious", clean: "Clean", no_api_key: "No API Key", failed: "Failed" }[status] ?? "Unknown";
}

function TooltipContent({ scannerKey, scanner }) {
  const meta = SCANNER_META[scannerKey];

  if (!scanner.success) {
    return (
      <div className="sr-tooltip-content">
        <div className="sr-tooltip-header">{meta.label}</div>
        <div className="sr-tooltip-error">{scanner.error || "Scanner unavailable"}</div>
      </div>
    );
  }

  if (scannerKey === "virustotal" && scanner.stats) {
    const s = scanner.stats;
    return (
      <div className="sr-tooltip-content">
        <div className="sr-tooltip-header">{meta.label}</div>
        {[["Malicious", s.malicious, "#fca5a5"], ["Suspicious", s.suspicious, "#fde68a"], ["Harmless", s.harmless, "#bbf7d0"], ["Undetected", s.undetected, "#94a3b8"]].map(([label, val, color]) => (
          <div key={label} className="sr-tooltip-row">
            <span>{label}</span>
            <span className="sr-tooltip-val" style={{ color }}>{val ?? 0}</span>
          </div>
        ))}
        {scanner.analysis_id && <div className="sr-tooltip-row sr-tooltip-analysis-id">ID: {scanner.analysis_id}</div>}
      </div>
    );
  }

  if (scannerKey === "otx") {
    return (
      <div className="sr-tooltip-content">
        <div className="sr-tooltip-header">{meta.label}</div>
        <div className="sr-tooltip-row">
          <span>Threat Pulses</span>
          <span className="sr-tooltip-val" style={{ color: scanner.pulse_count > 0 ? "#fca5a5" : "#bbf7d0" }}>{scanner.pulse_count ?? 0}</span>
        </div>
        <div className="sr-tooltip-row">
          <span>Verdict</span>
          <span className="sr-tooltip-val" style={{ color: VERDICT_COLOR[scanner.verdict] ?? "#e2e8f0" }}>{verdictLabel(scanner.verdict)}</span>
        </div>
      </div>
    );
  }

  if (scannerKey === "opencti") {
    return (
      <div className="sr-tooltip-content">
        <div className="sr-tooltip-header">{meta.label}</div>
        <div className="sr-tooltip-row">
          <span>Observable Found</span>
          <span className="sr-tooltip-val" style={{ color: scanner.observable_found ? "#fde68a" : "#bbf7d0" }}>{scanner.observable_found ? "Yes" : "No"}</span>
        </div>
        <div className="sr-tooltip-row">
          <span>Active Indicators</span>
          <span className="sr-tooltip-val" style={{ color: scanner.indicator_count > 0 ? "#fca5a5" : "#bbf7d0" }}>{scanner.indicator_count ?? 0}</span>
        </div>
        {scanner.indicators?.slice(0, 2).map((ind) => (
          <div key={ind.id} className="sr-tooltip-indicator">{ind.name || ind.pattern || ind.id}</div>
        ))}
      </div>
    );
  }

  return null;
}

function ScannerPill({ scannerKey, scanner }) {
  const [pos, setPos] = useState(null);
  const pillRef = useRef(null);
  const meta = SCANNER_META[scannerKey];
  const status = pillStatus(scanner);

  function showTooltip() {
    if (!pillRef.current) return;
    const rect = pillRef.current.getBoundingClientRect();
    setPos({ x: rect.left + rect.width / 2, y: rect.top });
  }

  return (
    <>
      <div
        ref={pillRef}
        className="sr-pill"
        onMouseEnter={showTooltip}
        onMouseLeave={() => setPos(null)}
      >
        <span className="sr-pill-dot" style={{ background: meta.dotColor }} />
        <span className="sr-pill-label">{meta.label}</span>
        <span className="sr-pill-verdict" style={{ color: VERDICT_COLOR[status] }}>{verdictLabel(status)}</span>
      </div>

      {pos && createPortal(
        <div className="sr-tooltip" style={{ left: pos.x, top: pos.y }}>
          <div className="sr-tooltip-arrow" />
          <TooltipContent scannerKey={scannerKey} scanner={scanner} />
        </div>,
        document.body
      )}
    </>
  );
}

function ScanRow({ item, index, total }) {
  const isLast = index === total - 1;
  const tdClass = `sr-td${isLast ? " sr-td--last" : ""}`;

  return (
    <tr>
      <td className={`${tdClass} sr-td-index`}>
        <span className="sr-index-num">{String(index + 1).padStart(2, "0")}</span>
      </td>
      <td className={`${tdClass} sr-td-url`}>
        <span className="sr-url-text">{item.target_url}</span>
      </td>
      <td className={tdClass}>
        <div className="sr-pills-row">
          {Object.entries(item.scanners).map(([key, scanner]) => (
            <ScannerPill key={key} scannerKey={key} scanner={scanner} />
          ))}
        </div>
      </td>
    </tr>
  );
}


export default function ScanResults({ data }) {
  const results = Array.isArray(data) ? data : [data];

  if (results.length <= 0){
    return (
      <div className="empty-data">
        No URLs to scan
      </div>
    )
  }

  return (
    <div className="sr-container">
      <div className="sr-scanline" />
      <div className="sr-header">
        <div className="sr-header-meta">HOVER FOR DETAILS</div>
      </div>
      <div className="sr-divider" />
      <div className="sr-table-wrapper">
        <table className="sr-table">
          <colgroup>
            <col className="sr-col-index" />
            <col className="sr-col-url" />
            <col className="sr-col-pills" />
          </colgroup>
          <tbody>
            {results.map((item, i) => (
              <ScanRow key={item.target_url + i} item={item} index={i} total={results.length} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
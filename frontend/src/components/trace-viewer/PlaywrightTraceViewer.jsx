import { useMemo } from 'react';
import { API_BASE } from '../../api';
import './PlaywrightTraceViewer.css';

const FALLBACK_TEXT = 'Playwright Trace Viewer is not available as trace_run_1.zip cannot be found';
const TRACE_VIEWER_URL = '/trace-viewer/index.html';

export default function PlaywrightTraceViewer({ traceViewer }) {
  const traceUrl = useMemo(
    () => (traceViewer?.status === 'available' ? traceViewer.traceUrl : null),
    [traceViewer]
  );

  if (!traceUrl) {
    return (
      <div className="ptv-fallback">
        {FALLBACK_TEXT}
      </div>
    );
  }
  const absoluteTraceUrl = new URL(traceUrl, API_BASE).toString();
  const src = `${TRACE_VIEWER_URL}?trace=${encodeURIComponent(absoluteTraceUrl)}`;

  return (
    <div className="ptv-frame-wrap">
      <iframe
        title="Playwright Trace Viewer"
        src={src}
        className="ptv-frame"
      />
    </div>
  );
}

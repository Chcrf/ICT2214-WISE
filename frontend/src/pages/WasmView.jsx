import { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileCode,
  ArrowLeft,
  Code2,
  Sparkles,
  BarChart3,
  Box,
  Search,
  Loader2
} from 'lucide-react';
import Prism from 'prismjs';
import 'prismjs/components/prism-c';
import 'prismjs/components/prism-wasm';
import 'prismjs/plugins/line-numbers/prism-line-numbers';
import 'prismjs/plugins/line-numbers/prism-line-numbers.css';
import 'prismjs/themes/prism-tomorrow.css';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import Navbar from '../components/Navbar';
import './WasmView.css';
import api from '../api';
// Sample analysis data - in real app this would come from API/props
import CopyJsonButton from '../components/CopyJsonButton';
import TraceSequence from '../components/TraceSequence';
import ScanResults from '../components/ScanResults';
import Artifacts from '../components/Artifacts';
import PlaywrightTraceViewer from '../components/trace-viewer/PlaywrightTraceViewer';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const mergeRequestsResponses = (requests = [], responses = []) => {
  const safeRequests = Array.isArray(requests) ? requests : [];
  const safeResponses = Array.isArray(responses) ? responses : [];
  const map = new Map();

  for (const r of safeRequests) {
    if (!r || typeof r !== 'object') continue;
    map.set(r.id, { id: r.id, request: r, response: null });
  }
  for (const s of safeResponses) {
    if (!s || typeof s !== 'object') continue;
    const entry = map.get(s.id) ?? { id: s.id, request: null, response: null };
    entry.response = s;
    map.set(s.id, entry);
  }

  return Array.from(map.values())
    .sort((a, b) => {
      const ta = (a.request?.timestamp ?? a.response?.timestamp) || 0;
      const tb = (b.request?.timestamp ?? b.response?.timestamp) || 0;
      return ta - tb;
    });
}

const DockerStats = ({ stats }) => {
  const formattedData = useMemo(() => {
    if (!stats) return [];
    return stats.map(s => ({
      ...s,
      time: new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      mem_mb: parseFloat((s.mem_bytes / 1024 / 1024).toFixed(2)),
      cpu_val: parseFloat(s.cpu_pct.toFixed(2))
    }));
  }, [stats]);

  if (formattedData.length === 0) {
    return (
      <div className="empty-data">
        No performance data available
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: 400 }}>
      <ResponsiveContainer>
        <LineChart data={formattedData}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-color)" />
          <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={12} tick={{ fill: 'var(--text-muted)' }} />
          <YAxis yAxisId="left" orientation="left" stroke="#8884d8" unit="%" tick={{ fill: 'var(--text-muted)' }} />
          <YAxis yAxisId="right" orientation="right" stroke="#82ca9d" unit="MB" tick={{ fill: 'var(--text-muted)' }} />
          <Tooltip
            contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)' }}
            itemStyle={{ color: 'var(--text-primary)' }}
          />
          <Legend />
          <Line yAxisId="left" type="monotone" dataKey="cpu_val" stroke="#8884d8" name="CPU %" dot={false} strokeWidth={2} />
          <Line yAxisId="right" type="monotone" dataKey="mem_mb" stroke="#82ca9d" name="Memory (MB)" dot={false} strokeWidth={2} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

const NetworkActivity = ({ network }) => {
  const pairs = Array.isArray(network) ? network : [];

  if (pairs.length === 0) {
    return (
      <div className="empty-data">
        No network activity data available
      </div>
    );
  }

  return (
    <div className="scrollable-box network-cards">
      {pairs.map((pair, i) => (
        <div className="net-card" key={pair.id || i}>
          <div className="net-card-left">
            <div className="net-card-header">
              <span className={`badge ${pair.request?.method || ''}`}>{pair.request?.method || 'N/A'}</span>
              <a className="net-url" href={pair.request?.url || '#'} target="_blank" rel="noreferrer" title={pair.request?.url || ''}>
                {pair.request?.url ? (pair.request.url.split('/').pop() || pair.request.url) : 'Unknown'}
              </a>
              <CopyJsonButton data={pair.request} label="Copy Request" />
            </div>
            <div className="net-card-body">
              <div className="meta">TS: {pair.request?.timestamp ?? '—'}</div>
              <pre className="net-pre">{pair.request ? JSON.stringify(pair.request, null, 2) : 'No request'}</pre>
            </div>
          </div>

          <div className={`net-card-right ${pair.response ? '' : 'pending'}`}>
            <div className="net-card-header">
              <span className="status">{pair.response ? pair.response.status : 'Pending'}</span>
              <span className="mime">{pair.response?.mimeType || '-'}</span>
              <CopyJsonButton data={pair.response} label="Copy Response" />
            </div>
            <div className="net-card-body">
              <div className="meta">TS: {pair.response?.timestamp ?? '—'}</div>
              <pre className="net-pre">{pair.response ? JSON.stringify(pair.response, null, 2) : 'Pending response'}</pre>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

const formatMetricLabel = (key) => String(key || '')
  .replace(/([a-z])([A-Z])/g, '$1 $2')
  .replace(/_/g, ' ')
  .replace(/\s+/g, ' ')
  .trim()
  .replace(/\b\w/g, (ch) => ch.toUpperCase());

const formatMetricValue = (value) => {
  if (value === null || value === undefined) return '—';
  const numeric = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(numeric) ? numeric.toLocaleString() : String(value);
};

const InstructionStatsGroup = ({ title, metrics }) => {
  if (!metrics || typeof metrics !== 'object') return null;
  const entries = Object.entries(metrics);
  if (!entries.length) return null;

  return (
    <div className="instruction-group">
      <h5>{title}</h5>
      <div className="instruction-metrics">
        {entries.map(([key, value]) => (
          <div className="instruction-metric" key={`${title}-${key}`}>
            <span className="instruction-metric-key">{formatMetricLabel(key)}</span>
            <span className="instruction-metric-value">{formatMetricValue(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const InstructionCounts = ({ runs }) => {
  const rows = useMemo(() => {
    const safeRuns = Array.isArray(runs) ? runs : [];
    return safeRuns
      .map((run, idx) => {
        const statistics = run?.wasm?.analysisResult?.statistics;
        if (!statistics || typeof statistics !== 'object') return null;

        const rawInstructions = statistics.instructions;
        const instructionCount = Number.isFinite(rawInstructions)
          ? rawInstructions
          : Number(rawInstructions);

        return {
          key: `${run?.runIndex ?? idx}-${run?.wasmFileName ?? 'unknown'}`,
          runIndex: run?.runIndex ?? idx + 1,
          wasmFileName: run?.wasmFileName ?? 'Unknown',
          instructionCount: Number.isFinite(instructionCount) ? instructionCount : null,
          statistics,
        };
      })
      .filter(Boolean);
  }, [runs]);

  const totalInstructions = useMemo(
    () => rows.reduce((sum, row) => sum + (row.instructionCount || 0), 0),
    [rows]
  );

  if (!rows.length) {
    return <div className="empty-data">No instruction statistics data available</div>;
  }

  return (
    <div className="instruction-counts">
      <div className="instruction-overview">
        <div className="instruction-stat-card">
          <h4>Total Instructions</h4>
          <p>{totalInstructions.toLocaleString()}</p>
        </div>
      </div>

      {rows.map((row) => (
        <details className="instruction-details" key={`${row.key}-details`} open={rows.length === 1}>
          <summary>
            Run {row.runIndex} detailed statistics ({row.wasmFileName})
          </summary>
          <div className="instruction-groups">
            <InstructionStatsGroup title="Blocks" metrics={row.statistics.blocks} />
            <InstructionStatsGroup title="Control Flow" metrics={row.statistics.controlFlow} />
            <InstructionStatsGroup title="Calls" metrics={row.statistics.calls} />
            <InstructionStatsGroup title="Numeric" metrics={row.statistics.numeric} />
            <InstructionStatsGroup title="Memory" metrics={row.statistics.memory} />
            <InstructionStatsGroup title="Variables" metrics={row.statistics.variables} />
          </div>
        </details>
      ))}
    </div>
  );
};

const SubsectionLoader = ({ label = 'Analyzing...' }) => (
  <div className="loading-state loading-state--small">
    <Loader2 className="spinner" size={20} />
    <p>{label}</p>
  </div>
);

const DynamicAnalysis = ({ data }) => {
  const dynamic = data?.dynamic ?? null;
  const functionMap = Array.isArray(data?.functionMap) ? data.functionMap : [];
  const hasFunctionMap = functionMap.length > 0;
  const [useLlmTraceNames, setUseLlmTraceNames] = useState(false);

  useEffect(() => {
    if (!hasFunctionMap && useLlmTraceNames) {
      setUseLlmTraceNames(false);
    }
  }, [hasFunctionMap, useLlmTraceNames]);

  const dockerStatsArray = dynamic?.docker?.stats || [];
  const currentRun = dynamic?.runs?.[0] || {};

  const requests = dynamic?.network?.requests;
  const responses = dynamic?.network?.responses;
  const pairs = useMemo(() => mergeRequestsResponses(requests, responses),
    [requests, responses]
  );

  const meta = {
    targetUrl: currentRun.targetWasmUrl || dynamic?.network?.targetWasmUrl || dynamic?.docker?.target_url || 'Unknown',
    generatedAt: dynamic?.meta?.generatedAt || 'Unknown',
  };

  const trace = currentRun.wasm?.analysisResult?.trace || [];
  const artifacts = dynamic?.artifacts || [];
  const traceViewer = data?.traceViewer || null;
  const threatIntelResults = Array.isArray(data?.threatIntel) ? data.threatIntel : [];

  if (data?.type === 'url') {
    return (
      <div className="dynamic-content">
        <p>This is a URL analysis record. Dynamic analysis can be viewed in the individual Wasm file analysis.</p>
      </div>
    );
  }

  if (!data?.parentId) {
    return (
      <div className="dynamic-content">
        <p>This is a File analysis record. Dynamic analysis is not available on file analysis.</p>
      </div>
    );
  }

  if (!dynamic) {
    return (
      <div className="dynamic-content">
        <p className="placeholder-text">No dynamic analysis data available.</p>
      </div>
    );
  }

  return (
    <div className="dynamic-content">
      <div className="dynamic-header">
        <div className="meta-card">
          <h4>Target</h4>
          <span>{meta.targetUrl}</span>
        </div>

        <div className="meta-card">
          <h4>Environment</h4>
          {currentRun.browser || dynamic ? (
            <span>Chromium</span>
          ) : (
            <span>Unknown</span>
          )}

        </div>

        <div className="meta-card">
          <h4>Generated At</h4>
          <span>{new Date(meta.generatedAt).toLocaleString()}</span>
        </div>
      </div>

      {/* Docker Performance Chart */}
      <div className="section-container">
        <h3>Container Performance</h3>
        {dockerStatsArray.length > 0 ? (
          <DockerStats stats={dockerStatsArray} />
        ) : (
          <SubsectionLoader label="Analyzing performance..." />
        )}
      </div>

      {/* Network Container */}
      <div className="section-container">
        <h3>Network Activity ({pairs.length})</h3>
        {pairs.length ? (
          <NetworkActivity network={pairs} />
        ) : (
          <div className="empty-data">No network activity data available</div>
        )}
      </div>

      {/* Threat Intelligence Container (cached backend data only) */}
      <div className="section-container">
        <h3>URLs Scanned ({threatIntelResults.length})</h3>
        {threatIntelResults.length ? (
          <ScanResults data={threatIntelResults} />
        ) : (
          <div className="empty-data">No cached CTI results available</div>
        )}
      </div>


      {/* Instruction Count Container */}
      <div className="section-container">
        <h3>Instruction Statistics (analysis_report.json)</h3>
        <InstructionCounts runs={dynamic?.runs} />
      </div>

      {/* Trace Display */}
      <div className="section-container">
        <div className="section-header">
          <h3>API Trace</h3>
          <label className={`trace-toggle ${hasFunctionMap ? '' : 'is-disabled'}`}>
            <input
              type="checkbox"
              checked={useLlmTraceNames}
              onChange={(event) => setUseLlmTraceNames(event.target.checked)}
              disabled={!hasFunctionMap}
            />
            <span>{hasFunctionMap ? 'Use LLM names' : 'LLM names unavailable'}</span>
          </label>
        </div>
        {trace.length ? (
          <TraceSequence trace={trace} functionMap={functionMap} useLlmNames={useLlmTraceNames} />
        ) : (
          <div className="empty-data">No API trace data available</div>
        )}
      </div>

      {/* To include artifacts to download, pcap files, log files */}
      <div className="section-container">
        <h3>Artifacts ({artifacts.length})</h3>
        {artifacts.length > 0 ? (
          <Artifacts files={artifacts} />
        ) : (
          <SubsectionLoader label="Collecting artifacts..." />
        )}
      </div>

      {/* For Playwright Trace Viewer */}
      <div className="section-container">
        <h3>Playwright Trace Viewer</h3>
        <div className="playwright_trace_viewer">
          {traceViewer ? (
            <PlaywrightTraceViewer traceViewer={traceViewer} />
          ) : (
            <SubsectionLoader label="Retrieving Trace Viewer zip file..." />
          )}
        </div>
      </div>
    </div>
  );
}

function WasmView() {
  const { id } = useParams();
  const [activeTab, setActiveTab] = useState('wasm-decompile');
  const [sampleAnalysisData, setSampleAnalysisData] = useState(null);
  const [traceViewer, setTraceViewer] = useState(null);

  const tabs = [
    { id: 'wasm-decompile', label: 'wasm-decompile', icon: Code2 },
    { id: 'ai-decompile', label: 'AI-decompile', icon: Sparkles },
    // new tab for the static/security report produced by the decompiler
    { id: 'static-analysis', label: 'Static Analysis', icon: Search },
    { id: 'dynamic-analysis', label: 'Dynamic Analysis', icon: Box },
    { id: 'analysis', label: 'Analysis', icon: BarChart3 },
  ];

  useEffect(() => {
    if (id) {
      getAnalysisData(id);
    }
  }, [id]);

  // highlight code unless it's extremely large, which can block UI
  useEffect(() => {
    const data = sampleAnalysisData || {};
    let text = '';
    switch (activeTab) {
      case 'wasm-decompile':
        text = data.wasmDecompile || '';
        break;
      case 'ai-decompile':
        text = data.aiDecompile || '';
        break;
      default:
        text = '';
    }
    if (text.length < 200_000) {
      Prism.highlightAll();
    }
  }, [activeTab, sampleAnalysisData]);

  // API
  const getAnalysisData = async (hash) => {
    try {
      const response = await api.get(`/analysis/${hash}`);
      setSampleAnalysisData(response.data.analysis_data);
    } catch (error) {
      console.error('Analysis failed:', error);
    }
  };

  const getTraceViewer = async (investigationId) => {
    try {
      const response = await api.get(`/trace-viewer/${investigationId}`);
      setTraceViewer(response.data || null);
    } catch {
      setTraceViewer({ status: 'missing', message: 'trace-viewer file does not exist' });
    }
  };

  useEffect(() => {
    const investigationId = sampleAnalysisData?.investigationId;
    if (investigationId && sampleAnalysisData?.dynamic) {
      getTraceViewer(investigationId);
    }
  }, [sampleAnalysisData]);


  const renderCodeContent = () => {
    const data = sampleAnalysisData || {};
    switch (activeTab) {
      case 'wasm-decompile':
        return (
          <pre className="code-block line-numbers language-wasm">
            <code className="language-wasm">{data.wasmDecompile || '// Pending analysis...'}</code>
          </pre>
        );
      case 'ai-decompile':
        return (
          <pre className="code-block ai-enhanced line-numbers language-c">
            <code className="language-c">{data.aiDecompile || '// Pending AI-enhanced decompilation...'}</code>
          </pre>
        );
      case 'static-analysis':
        return renderSecurityFindings();
      case 'analysis':
        return renderAnalysis();
      case 'dynamic-analysis':
        return (
          <DynamicAnalysis data={sampleAnalysisData ? { ...sampleAnalysisData, traceViewer } : { traceViewer }} />
        );
      default:
        return null;
    }
  };

  const renderAnalysis = () => {
    const analysis = sampleAnalysisData?.analysis;
    if (!analysis) {
      return (
        <div className="analysis-content">
          <p>No analysis data available yet.</p>
        </div>
      );
    }

    const yaraRule = typeof analysis.yaraRule === 'string' ? analysis.yaraRule : '';
    const hasYaraRule = Boolean(yaraRule && yaraRule.trim());

    return (
      <div className="analysis-content">
        <div className="analysis-section">
          <h3>Summary</h3>
          <div className="analysis-summary-markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {analysis.summary || 'Analysis pending...'}
            </ReactMarkdown>
          </div>
          {analysis.summary === "Static analysis disabled. Decompilation outputs only." && (
            <p style={{ fontStyle: 'italic', color: '#666' }}>
              (Static analysis is not yet implemented; only wasm decompilation
              results are available.)
            </p>
          )}
        </div>

        <div className="analysis-section">
          <div className="analysis-section-header">
            <h3>YARA Rule</h3>
            <CopyJsonButton data={hasYaraRule ? yaraRule : ''} label="Copy YARA" />
          </div>
          {hasYaraRule ? (
            <pre className="code-block yara-block">
              <code>{yaraRule}</code>
            </pre>
          ) : (
            <p className="placeholder-text">No YARA rule available yet.</p>
          )}
        </div>

      </div>
    );
  };

  const renderSecurityFindings = () => {
    const data = sampleAnalysisData || {};
    if (data.type === 'url') {
      return (
        <div className="analysis-content">
          <p>This is a URL analysis record. Static metadata is not available for URL parents.</p>
        </div>
      );
    }
    const staticData = data.staticAnalysis || {};
    const analysis = data.analysis || {};
    const functions = Array.isArray(analysis.functions) ? analysis.functions : [];
    const exports = Array.isArray(analysis.exports) ? analysis.exports : [];
    const imports = Array.isArray(analysis.imports) ? analysis.imports : [];
    const fileInfo = staticData.fileInfo || data.fileInfo || {};
    const hashesRaw = staticData.hashes || data.hashes || {};
    const stringsRaw = staticData.strings || data.strings || [];
    const findings = Array.isArray(data.securityFindings) ? data.securityFindings : [];

    const fileName = fileInfo.name || data.sampleName || 'Unknown';
    const fileType = fileInfo.type || 'Unknown';
    const fileSize = fileInfo.size_formatted || (fileInfo.size ? `${fileInfo.size} bytes` : 'Unknown');

    const hashes = { ...hashesRaw };
    if (!hashes.sha256 && data.hash) {
      hashes.sha256 = data.hash;
    }
    const preferredHashOrder = ['md5', 'sha1', 'sha256', 'ssdeep', 'sha512', 'sha384', 'sha224', 'blake2b', 'blake2s'];
    const hashEntries = [];
    const seenHashes = new Set();
    preferredHashOrder.forEach((key) => {
      if (hashes[key]) {
        hashEntries.push([key, hashes[key]]);
        seenHashes.add(key);
      }
    });
    Object.entries(hashes).forEach(([key, value]) => {
      if (!seenHashes.has(key)) {
        hashEntries.push([key, value]);
      }
    });

    const strings = Array.isArray(stringsRaw)
      ? stringsRaw
      : typeof stringsRaw === 'string'
        ? stringsRaw.split('\n').filter(Boolean)
        : [];
    const stringsPreview = strings.length > 0 ? strings.join('\n') : '';

    return (
      <div className="analysis-content">
        <div className="analysis-section">
          <h3>Static Analysis Metadata</h3>
          <div className="analysis-grid static-meta-grid">
            <div className="analysis-card static-meta-card">
              <h4>Filename</h4>
              <span>{fileName}</span>
            </div>
            <div className="analysis-card static-meta-card">
              <h4>File Type</h4>
              <span>{fileType}</span>
            </div>
            <div className="analysis-card static-meta-card">
              <h4>File Size</h4>
              <span>{fileSize}</span>
            </div>
          </div>
        </div>

        <div className="analysis-section">
          <h3>Hashes</h3>
          {hashEntries.length === 0 ? (
            <p className="placeholder-text">Hash data not available yet.</p>
          ) : (
            <div className="hash-list">
              {hashEntries.map(([key, value]) => (
                <div className="hash-item" key={key}>
                  <span className="hash-label">{key.toUpperCase()}</span>
                  <span className="hash-sep">:</span>
                  <code className="hash-value">{value}</code>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="analysis-section">
          <h3>Exports</h3>
          <div className="function-list">
            {functions.map((func, idx) => {
              const isString = typeof func === 'string';
              const name = isString ? func : func.name;
              const description = isString ? null : func.description;
              const risk = isString ? null : func.risk;

              return (
                <div key={idx} className="function-item">
                  <div className="function-name">
                    <FileCode size={16} />
                    <code>{name}</code>
                  </div>
                  {description && <div className="function-desc">{description}</div>}
                  {risk && <span className={`function-risk ${risk}`}>{risk}</span>}
                </div>
              );
            })}
          </div>
          <div className="exports-inline">
            {exports.length === 0 ? (
              <p className="placeholder-text">No exports found.</p>
            ) : (
              <div className="exports-list">
                {exports.map((exp, idx) => (
                  <code key={idx} className="export-item">{exp}</code>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="analysis-section">
          <h3>Imports</h3>
          {imports.length === 0 ? (
            <p className="placeholder-text">No imports found.</p>
          ) : (
            <div className="exports-list">
              {imports.map((imp, idx) => (
                <code key={idx} className="export-item">{imp}</code>
              ))}
            </div>
          )}
        </div>

        <div className="analysis-section">
          <h3>Strings</h3>
          <details className="strings-collapsible" open>
            <summary>
              Strings ({strings.length})
            </summary>
            <div className="strings-body">
              {strings.length === 0 ? (
                <p className="placeholder-text">No extracted strings available yet.</p>
              ) : (
                <pre className="code-block strings-block">
                  <code>{stringsPreview}</code>
                </pre>
              )}
            </div>
          </details>
        </div>

        <div className="analysis-section">
          <h3>Vulnerabilities</h3>
          <details className="findings-collapsible" open>
            <summary>
              AI Vulnerability Findings ({findings.length})
            </summary>
            <div className="findings-body">
              {findings.length === 0 && (
                <div className="empty-data">No security findings available yet.</div>
              )}
              {findings.map((finding, idx) => (
                <div key={idx} className="finding-card">
                  <div className="finding-header">
                    <span className="finding-type">{finding.vulnerability_type}</span>
                    <span className={`risk-badge ${(finding.confidence_score || '').toLowerCase()}`}>
                      {finding.confidence_score}
                    </span>
                  </div>
                  {finding.line_numbers && (
                    <div className="finding-lines">{finding.line_numbers}</div>
                  )}
                  <div className="finding-section">
                    <h4>Evidence</h4>
                    <pre className="code-block">
                      <code className="language-c">{finding.evidence_code}</code>
                    </pre>
                  </div>
                  <div className="finding-section">
                    <h4>Explanation</h4>
                    <p>{finding.explanation}</p>
                  </div>
                  <div className="finding-section">
                    <h4>Recommended Fix</h4>
                    <p>{finding.fix}</p>
                  </div>
                </div>
              ))}
            </div>
          </details>
        </div>
      </div>
    );
  };

  return (
    <div className="app wasm-app">
      <Navbar />

      <div className="wasm-view-container">
        {/* Tabs Header */}
        <div className="wasm-tabs-header">
          <div className="wasm-tabs">
            {tabs.map((tab) => {
              const IconComponent = tab.icon;
              return (
                <button
                  key={tab.id}
                  className={`wasm-tab ${activeTab === tab.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                >
                  <IconComponent size={14} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Main Content */}
        <main className="wasm-main-content">
          <div className="content-header">
            <Link to="/investigations" className="back-link">
              <ArrowLeft size={16} />
              Back to Investigations
            </Link>
            <h2>{tabs.find(t => t.id === activeTab)?.label}</h2>
            {sampleAnalysisData?.parent?.url && (
              <p className="parent-url">Parent URL: {sampleAnalysisData.parent.url}</p>
            )}
          </div>
          <div className="code-container">
            {renderCodeContent()}
          </div>
        </main>
      </div>
    </div>
  );
}

export default WasmView;

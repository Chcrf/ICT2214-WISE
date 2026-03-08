import { useMemo } from 'react';
import './TraceSequence.css';


const parseSignature = (signature) => {
  const match = signature.match(/(\w+|\d+)\s*->\s*(\w+|\d+)/);
  if (match) {
    return [match[1], match[2]];
  }
  return ['0', '0'];
};

const buildFunctionNameMap = (functionMap) => {
  const map = new Map();
  if (!Array.isArray(functionMap)) return map;
  for (const entry of functionMap) {
    if (!entry || typeof entry !== 'object') continue;
    const key = String(entry.index);
    const name = entry.llm_name || entry.wat_name;
    if (name) {
      map.set(key, name);
    }
  }
  return map;
};

const resolveFunctionName = (name, useLlmNames, nameMap) => {
  if (!useLlmNames) return name;
  if (!name) return name;
  if (!/^\d+$/.test(name)) return name;
  return nameMap.get(name) || name;
};

export default function TraceSequence({ trace, functionMap, useLlmNames = false }) {
  // Keep trace in sequence with hierarchy
  const functionNameMap = useMemo(() => buildFunctionNameMap(functionMap), [functionMap]);

  const sequenceList = useMemo(() => {
    if (!trace || trace.length === 0) return [];

    const result = [];
    let currentSource = null;
    let sourceDepth = null;

    for (let i = 0; i < trace.length; i++) {
      const t = trace[i];
      const [rawSource, rawTarget] = parseSignature(t.signature);
      const source = resolveFunctionName(rawSource, useLlmNames, functionNameMap);
      const target = resolveFunctionName(rawTarget, useLlmNames, functionNameMap);
      const depth = t.depth || 0;

      // When source changes, add a source header
      if (source !== currentSource) {
        currentSource = source;
        sourceDepth = depth;
        result.push({
          type: 'source',
          lineNum: i + 1,
          source,
          depth,
          isHeader: true
        });
      }

      // Add the target call as a child
        result.push({
          type: 'target',
          lineNum: i + 1,
          source,
          target,
          signature: `${source} → ${target}`,
          depth,
          args: t.args || [],
          isChild: true
        });
      }

      return result;
  }, [trace, useLlmNames, functionNameMap]);

  if (sequenceList.length === 0) {
    return (
      <div className="trace-empty">No trace data available</div>
    )
  };
  
  return (
    <div className="trace-sequence-container">
      {/* Header */}
      <div className="trace-sequence-header">
        <div className="trace-sequence-info">
          <span>{trace?.length || 0} total calls</span>
          <div className="legend-row">
            <span className="legend-item"><span className="source-func">■</span> Source Function</span>
            <span className="legend-item"><span className="target-func">■</span> Target Function</span>
            <span className="legend-item"><span className="target-args">■</span> Arguments</span>
          </div>
        </div>
      </div>

      {/* Sequence View */}
      <div className="trace-sequence-wrapper">
        
          <div className="trace-sequence">
            {sequenceList.map((item, idx) => {
              // Check if next item is a source or last target
              const isLastOfSource = idx + 1 >= sequenceList.length || sequenceList[idx + 1].type === 'source';
              const prefix = isLastOfSource ? '└─' : '├─';
              
              if (item.type === 'source') {
                return (
                  <div key={`src-${idx}`} className="trace-sequence-item source-header">
                    <div className="sequence-line-num"></div>
                    <div className="sequence-content">
                      <div className="sequence-source">
                        <span className="depth-dashes">{"| ".repeat(item.depth)}</span>
                        <span className="source-func">{item.source}</span>
                      </div>
                    </div>
                  </div>
                );
              }

              return (
                <div key={`tgt-${idx}`} className="trace-sequence-item target-call">
                  <div className="sequence-line-num">{item.lineNum}</div>
                  <div className="sequence-content">
                    <div className="sequence-call">
                      <span className="depth-dashes">{"| ".repeat(item.depth)}{prefix}</span>
                      <span className="target-func">{item.target}</span>
                      {item.args.length > 0 && (
                        <span className="target-args">({item.args.join(', ')})</span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
      </div>
    </div>
  );
}

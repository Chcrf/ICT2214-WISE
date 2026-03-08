import { useState, useEffect } from 'react';
import { Copy } from 'lucide-react';

export default function CopyJsonButton({ data, label = 'Copy', size = 14 }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let id;
    if (copied) id = setTimeout(() => setCopied(false), 1800);
    return () => clearTimeout(id);
  }, [copied]);

  const handleCopy = async (e) => {
    e?.stopPropagation();
    if (!data) return;
    const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch (err) {
      // fallback
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        setCopied(true);
      } catch (e) {
        console.error('Copy failed', e);
      }
    }
  };

  return (
    <button
      className={`copy-btn`}
      onClick={handleCopy}
      disabled={!data}
      title={copied ? 'Copied' : label}
      type="button"
    >
      <Copy size={size} />
      <span className="copy-label">{copied ? 'Copied' : label}</span>
    </button>
  );
}

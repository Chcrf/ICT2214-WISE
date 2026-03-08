import { useState } from 'react';
import { 
  Upload, 
  Link, 
  Shield,
  Fingerprint,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Loader2,
  ExternalLink,
} from 'lucide-react';
import { Link as RouterLink } from 'react-router-dom';
import api from './api';
import Navbar from './components/Navbar';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('file');
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [urlInput, setUrlInput] = useState('');

  const handleFileDrop = async (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer?.files[0] || e.target?.files[0];
    if (file) {
      await analyzeFile(file);
    }
  };

  const analyzeFile = async (file) => {
    setIsLoading(true);
    setAnalysisResult(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await api.post('/analyze/file', formData);
      setAnalysisResult(response.data);
    } catch (error) {
      console.error('Analysis failed:', error);
      setAnalysisResult({ error: 'Analysis failed. Please try again.' });
    }
    setIsLoading(false);
  };

  const analyzeUrl = async () => {
    if (!urlInput.trim()) return;
    setIsLoading(true);
    setAnalysisResult(null);
    try {
      const response = await api.post('/analyze/url', { url: urlInput });
      setAnalysisResult(response.data);
    } catch (error) {
      console.error('URL analysis failed:', error);
      setAnalysisResult({ error: 'URL analysis failed. Please try again.' });
    }
    setIsLoading(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  return (
    <div className="app">
      <Navbar />

      {/* Main Content */}
      <main className="main-content">
        {/* Hero Section */}
        <div className="hero">
          <div className="logo-large">
            <Shield className="hero-icon" />
            <h1>WISE</h1>
          </div>
          <p className="tagline">
            Analyse suspicious files, domains, IPs and URLs to detect malware and other
            <br />breaches, automatically share them with the security community.
          </p>
        </div>

        {/* Tabs */}
        <div className="tabs-container">
          <div className="tabs">
            <button 
              className={`tab ${activeTab === 'file' ? 'active' : ''}`}
              onClick={() => setActiveTab('file')}
            >
              <Upload size={18} />
              FILE
            </button>
            <button 
              className={`tab ${activeTab === 'url' ? 'active' : ''}`}
              onClick={() => setActiveTab('url')}
            >
              <Link size={18} />
              URL
            </button>
          </div>

          {/* Tab Content */}
          <div className="tab-content">
            {activeTab === 'file' && (
              <div 
                className={`upload-zone ${isDragging ? 'dragging' : ''}`}
                onDrop={handleFileDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
              >
                <div className="upload-icon">
                  <Fingerprint size={64} strokeWidth={1} />
                </div>
                <label className="upload-btn">
                  <input 
                    type="file" 
                    onChange={handleFileDrop}
                    style={{ display: 'none' }}
                  />
                  Choose file
                </label>
                <p className="upload-hint">or drag and drop a file here</p>
              </div>
            )}

            {activeTab === 'url' && (
              <div className="url-input-container">
                <div className="url-input-wrapper">
                  <Link size={20} className="url-icon" />
                  <input
                    type="text"
                    placeholder="Enter URL to analyze (e.g., https://example.com)"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeUrl()}
                    className="url-input"
                  />
                  <button className="analyze-btn" onClick={analyzeUrl}>
                    <ChevronRight size={24} />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="loading-state">
            <Loader2 className="spinner" size={48} />
            <p>Analyzing...</p>
          </div>
        )}

        {/* Analysis Result */}
        {analysisResult && !isLoading && (
          <div className="result-card">
            {analysisResult.error ? (
              <div className="result-error">
                <AlertTriangle size={24} />
                <span>{analysisResult.error}</span>
              </div>
            ) : (
              <div className="result-success">
                <div className="result-header">
                  <CheckCircle size={24} />
                  <span>File Uploaded Successfully</span>
                </div>
                <div className="result-details">
                  <div className="detail-item">
                    <span className="label">File Name:</span>
                    <span className="value">{analysisResult.file_info?.name || 'Unknown'}</span>
                  </div>
                  <div className="detail-item">
                    <span className="label">Status:</span>
                    <span className="value status-queued">Queued for Analysis</span>
                  </div>
                </div>
                <div className="result-actions">
                  <RouterLink to="/investigations" className="view-investigations-btn">
                    <ExternalLink size={18} />
                    View in Investigations
                  </RouterLink>
                </div>
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
}

export default App;

import { useState, Fragment, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, FileText, CheckCircle, XCircle, Clock, AlertTriangle, Search } from 'lucide-react';
import Navbar from '../components/Navbar';
import './Investigations.css';
import api from '../api';

function Investigations() {
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [investigations, setInvestigations] = useState([]);
  const [hashSearch, setHashSearch] = useState('');

  // Fetch investigations on mount and poll every 5 seconds for updates
  useEffect(() => {
    getInvestigations();
    const interval = setInterval(getInvestigations, 5000);
    return () => clearInterval(interval);
  }, []);
  
  // APIS
  const getInvestigations = async () => {
    try {
      const response = await api.get('/investigations');
      setInvestigations(response.data.investigations);
    } catch (error) {
      console.error('Retrieval failed:', error);
    }
  }

  const reanalyze = async (hash) => {
    try {
      const response = await api.post(`/reanalyze/${hash}`);
      if (response.data.success) {
        alert('Re-analysis queued successfully');
        // Refresh investigations list
        getInvestigations();
      }
    } catch (error) {
      console.error('Re-analyze failed:', error);
      alert('Failed to queue re-analysis: ' + (error.response?.data?.detail || error.message));
    }
  }

  const filteredInvestigations = investigations.filter(item => {
    const needle = hashSearch.toLowerCase();
    const selfMatch =
      item.hash.toLowerCase().includes(needle) ||
      item.sampleName.toLowerCase().includes(needle);
    const childMatch = Array.isArray(item.children) && item.children.some(child =>
      child.hash.toLowerCase().includes(needle) ||
      child.sampleName.toLowerCase().includes(needle)
    );
    return selfMatch || childMatch;
  });



  const toggleRow = (id) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRows(newExpanded);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle size={16} className="status-icon completed" />;
      case 'analyzing':
        return <Clock size={16} className="status-icon analyzing" />;
      case 'failed':
        return <XCircle size={16} className="status-icon failed" />;
      default:
        return <Clock size={16} className="status-icon" />;
    }
  };

  return (
    <div className="app">
      <Navbar />
      
      <main className="investigations-content">
        <div className="investigations-header">
          <h1>Investigations</h1>
          <p className="investigations-subtitle">View and manage your sample analysis history</p>
        </div>

        <div className="investigations-search">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search by hash or sample name..."
            value={hashSearch}
            onChange={(e) => setHashSearch(e.target.value)}
          />
        </div>

        <div className="investigations-table-container">
          <table className="investigations-table">
            <thead>
              <tr>
                <th className="expand-col"></th>
                <th>Hash</th>
                <th>Sample Name</th>
                <th>Status</th>
                <th>Sample Lost</th>
              </tr>
            </thead>
            <tbody>
              {filteredInvestigations.map((item) => {
                const isUrl = item.investigation_type === 'url';
                const childCount = Array.isArray(item.children) ? item.children.length : 0;
                return (
                <Fragment key={item.id}>
                  <tr 
                    className={`investigation-row ${expandedRows.has(item.id) ? 'expanded' : ''}`}
                    onClick={() => toggleRow(item.id)}
                  >
                    <td className="expand-col">
                      <button className="expand-btn">
                        {expandedRows.has(item.id) ? (
                          <ChevronDown size={18} />
                        ) : (
                          <ChevronRight size={18} />
                        )}
                      </button>
                    </td>
                    <td className="hash-cell">
                      <code>{item.hash.substring(0, 16)}...</code>
                    </td>
                    <td className="name-cell">
                      <FileText size={16} />
                      <span>{item.sampleName}</span>
                      {isUrl && (
                        <span className="type-badge">URL ({childCount} WASM)</span>
                      )}
                    </td>
                    <td className="status-cell">
                      {getStatusIcon(item.status)}
                      <span className={`status-text ${item.status}`}>
                        {item.status.charAt(0).toUpperCase() + item.status.slice(1)}
                      </span>
                    </td>
                    <td className="lost-cell">
                      {isUrl ? (
                        <span className="available-badge">N/A</span>
                      ) : item.sampleLost ? (
                        <span className="lost-badge">
                          <AlertTriangle size={14} />
                          Lost
                        </span>
                      ) : (
                        <span className="available-badge">Available</span>
                      )}
                    </td>
                  </tr>
                  {expandedRows.has(item.id) && (
                    <tr className="expanded-row">
                      <td colSpan="5">
                        <div className="expanded-content">
                          <div className="expanded-section">
                            <h4>SHA-256 HASH</h4>
                            <code className="full-hash">{item.hash}</code>
                          </div>
                          {isUrl ? (
                            <div className="expanded-section">
                              <h4>Discovered WASM</h4>
                              {childCount === 0 ? (
                                <p className="placeholder-text">No WASM files discovered yet.</p>
                              ) : (
                                <div className="child-table">
                                  {item.children.map((child) => (
                                    <div key={child.id} className="child-row">
                                      <div className="child-name">
                                        <FileText size={14} />
                                        <span>{child.sampleName}</span>
                                      </div>
                                      <div className="child-hash">
                                        <code>{child.hash.substring(0, 12)}...</code>
                                      </div>
                                      <div className="child-status">
                                        {getStatusIcon(child.status)}
                                        <span className={`status-text ${child.status}`}>{child.status}</span>
                                      </div>
                                      <div className="child-actions">
                                        <Link to={`/analysis/${child.hash}`} className="action-btn primary">View</Link>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="expanded-section">
                              <h4>Details</h4>
                            </div>
                          )}
                          <div className="expanded-actions">
                            {!isUrl && (
                              <Link to={`/analysis/${item.hash}`} className="action-btn primary">View Full Report</Link>
                            )}
                            {isUrl && (
                              <Link to={`/analysis/${item.hash}`} className="action-btn primary">View URL Analysis</Link>
                            )}
                            <button className="action-btn secondary" onClick={() => reanalyze(item.hash)}>Re-analyze</button>
                            {!isUrl && (
                              <button className="action-btn secondary">Download Sample</button>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )})}
            </tbody>
          </table>

          {investigations.length === 0 && (
            <div className="empty-state">
              <FileText size={48} />
              <h3>No Investigations Yet</h3>
              <p>Upload a file or analyze a URL to start your first investigation.</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default Investigations;

import { Link, useLocation } from 'react-router-dom';
import { Shield, Search, Network, Layers } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import api from '../api';
import './Navbar.css';

function Navbar() {
  const [searchInput, setSearchInput] = useState('');
  const [isProcessMenuOpen, setIsProcessMenuOpen] = useState(false);
  const [currentProcess, setCurrentProcess] = useState(null);
  const [queue, setQueue] = useState([]);
  const [completed, setCompleted] = useState([]);
  const [failed, setFailed] = useState([]);
  const location = useLocation();
  const menuRef = useRef(null);

  const handleSearch = async () => {
    if (!searchInput.trim()) return;
    try {
      const response = await api.post('/analyze/url', { url: searchInput.trim() });
      if (response.data?.success) {
        alert('URL analysis queued. Check Investigations for status.');
      }
    } catch (error) {
      console.error('URL analysis failed:', error);
      alert('Failed to queue URL analysis: ' + (error.response?.data?.detail || error.message));
    }
  };

  // Fetch queue status from backend
  const fetchQueueStatus = async () => {
    try {
      const response = await api.get('/queue/status');
      if (response.data.success) {
        setCurrentProcess(response.data.currentProcess);
        setQueue(response.data.queue || []);
        setCompleted(response.data.completed || []);
        setFailed(response.data.failed || []);
      }
    } catch (error) {
      console.error('Failed to fetch queue status:', error);
    }
  };

  // Fetch queue status on mount and periodically
  useEffect(() => {
    fetchQueueStatus();
    const interval = setInterval(fetchQueueStatus, 5000); // Poll every 5 seconds
    return () => {
      clearInterval(interval);
    };
  }, []);

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsProcessMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getStatusClass = (status) => {
    switch (status) {
      case 'done': return 'hex-done';
      case 'in-progress': return 'hex-progress';
      case 'pending': return 'hex-pending';
      default: return 'hex-pending';
    }
  };

  return (
    <header className="header">
      <Link to="/" className="header-left">
        <Shield className="logo-icon" />
        <span className="logo-text">WISE</span>
      </Link>
      <div className="search-bar">
        <Search size={18} />
        <input 
          type="text" 
          placeholder="URL, IP address, domain or file hash" 
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
        />
      </div>
      <div className="header-divider"></div>
      <div className="header-right">
        <Link 
          to="/investigations" 
          className={`icon-btn ${location.pathname === '/investigations' ? 'active' : ''}`}
          data-tooltip="Investigations"
        >
          <Network size={20} />
        </Link>
        
        {/* Process Queue Button & Dropdown */}
        <div className="process-menu-wrapper" ref={menuRef}>
          <button 
            className={`icon-btn ${isProcessMenuOpen ? 'active' : ''}`}
            onClick={() => setIsProcessMenuOpen(!isProcessMenuOpen)}
            data-tooltip="Process Queue"
          >
            <Layers size={20} />
          </button>
          
          {/* Dropdown Panel */}
          <div className={`process-dropdown ${isProcessMenuOpen ? 'open' : ''}`}>
            {/* Currently Processing */}
            <div className="dropdown-section">
              <h4 className="dropdown-title">Currently Processing</h4>
              {currentProcess ? (
                <>
                  <div className="current-sample">{currentProcess.name}</div>
                  
                  {/* Hexagon Process Flow */}
                  <div className="hex-flow">
                    {currentProcess.stages.map((stage, index) => (
                      <div key={stage.id} className="hex-stage">
                        <div className={`hex ${getStatusClass(stage.status)}`}>
                          <span className="hex-text">{stage.name}</span>
                        </div>
                        {index < currentProcess.stages.length - 1 && (
                          <div className={`hex-connector ${currentProcess.stages[index].status === 'done' ? 'done' : ''}`}></div>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="no-process">No active processing</div>
              )}
            </div>

            {/* Queue */}
            <div className="dropdown-section">
              <div className="dropdown-header">
                <h4 className="dropdown-title">Queue</h4>
                <span className="dropdown-count">{queue.length}</span>
              </div>
              <div className="dropdown-list">
                {queue.map((item, index) => (
                  <div key={index} className="dropdown-item queue">
                    <span className="item-dot"></span>
                    <span>{item.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Completed */}
            <div className="dropdown-section">
              <div className="dropdown-header">
                <h4 className="dropdown-title">Completed</h4>
                <span className="dropdown-count success">{completed.length}</span>
              </div>
              <div className="dropdown-list">
                {completed.map((item, index) => (
                  <div key={index} className="dropdown-item completed">
                    <span className="item-dot"></span>
                    <span>{item.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Failed */}
            {failed.length > 0 && (
              <div className="dropdown-section">
                <div className="dropdown-header">
                  <h4 className="dropdown-title">Failed</h4>
                  <span className="dropdown-count failed">{failed.length}</span>
                </div>
                <div className="dropdown-list">
                  {failed.map((item, index) => (
                    <div key={index} className="dropdown-item failed">
                      <span className="item-dot"></span>
                      <span>{item.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>
        </div>
      </div>
    </header>
  );
}

export default Navbar;

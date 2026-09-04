import { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle } from 'lucide-react';
import { apiClient } from './api/client';

import Sidebar from './components/Sidebar';
import Header from './components/Header';
import UploadZone from './components/UploadZone';
import ScoreOverview from './components/ScoreOverview';
import DeviceInfo from './components/DeviceInfo';
import FindingsTable from './components/FindingsTable';
import FindingDetail from './components/FindingDetail';
import RemediationView from './components/RemediationView';
import BeforeAfter from './components/BeforeAfter';
import HistoryView from './components/HistoryView';
import { saveScanToHistory } from './utils/history';

function LoadingState() {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const intervals = [
      setTimeout(() => setStep(1), 800),
      setTimeout(() => setStep(2), 1500),
      setTimeout(() => setStep(3), 2200),
      setTimeout(() => setStep(4), 2800)
    ];
    return () => intervals.forEach(clearTimeout);
  }, []);

  const steps = [
    'Parsing configuration',
    'Detecting devices',
    'Running security rules',
    'Generating findings',
    'Calculating security score'
  ];

  return (
    <div className="upload-wrapper">
      <div className="loading-steps">
        <div style={{ marginBottom: '1rem', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '0.05em' }}>
          ANALYZING CONFIGURATION
        </div>
        {steps.map((s, i) => (
          <div key={i} className={`loading-step ${i < step ? 'done' : (i === step ? 'active' : '')}`}>
            {i < step ? (
              <CheckCircle size={14} color="var(--success)" />
            ) : i === step ? (
              <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
            ) : (
              <span style={{ width: 14, height: 14, borderRadius: '50%', border: '2px solid var(--border)' }} />
            )}
            {s}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState('upload'); // upload | loading | dashboard | devices | findings | history
  const [error, setError] = useState(null);
  const [scanResult, setScanResult] = useState(null);

  const [selectedFinding, setSelectedFinding] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [notification, setNotification] = useState(null);

  const showNotification = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 3000);
  };

  const handleUpload = async (files) => {
    setView('loading');
    setError(null);
    try {
      const result = await apiClient.scanConfigs(files);
      setScanResult(result);
      saveScanToHistory(result);
      setView('dashboard');
      showNotification('Scan completed successfully');
    } catch (err) {
      setError(err.message);
      setView('upload');
    }
  };

  const handleNewScan = () => {
    setView('upload');
    setScanResult(null);
    setSelectedFinding(null);
    setRemediation(null);
    setComparison(null);
    setError(null);
  };

  const handleSelectFinding = (finding) => {
    setSelectedFinding(finding);
    setRemediation(null);
    setComparison(null);
  };

  const handleRemediation = (rem) => {
    setSelectedFinding(null);
    setRemediation(rem);
  };

  const handleVerified = (result) => {
    setRemediation(null);
    setComparison(result);
  };

  const handleCloseModal = () => {
    setSelectedFinding(null);
    setRemediation(null);
    setComparison(null);
  };

  const handleSelectHistoryEntry = (fullResult) => {
    setScanResult(fullResult);
    setView('dashboard');
  };

  return (
    <div className="app-layout">
      <Sidebar view={view} setView={setView} devices={scanResult?.devices} />
      
      <div className="main-wrapper">
        <Header 
          onNewScan={handleNewScan}
          timestamp={scanResult?.timestamp}
        />

        <main className="main-content">
          <div className="dashboard-container">
            {error && (
              <div style={{ backgroundColor: 'var(--critical-bg)', border: '1px solid var(--critical-border)', padding: '1rem', borderRadius: 'var(--radius)', color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertCircle size={16} />
                {error}
              </div>
            )}

            {view === 'upload' && <UploadZone onUpload={handleUpload} />}

            {view === 'loading' && <LoadingState />}

            {view === 'dashboard' && scanResult && (
              <>
                <ScoreOverview 
                  score={scanResult.score} 
                  critical={scanResult.critical}
                  high={scanResult.high}
                  medium={scanResult.medium}
                  low={scanResult.low}
                />
                
                <FindingsTable
                  findings={scanResult.findings}
                  onSelectFinding={handleSelectFinding}
                />
              </>
            )}
            
            {view === 'devices' && scanResult && (
              <DeviceInfo devices={scanResult.devices} findings={scanResult.findings} />
            )}
            
            {view === 'findings' && scanResult && (
              <FindingsTable
                findings={scanResult.findings}
                onSelectFinding={handleSelectFinding}
              />
            )}

            {view === 'history' && (
              <HistoryView onSelectHistoryEntry={handleSelectHistoryEntry} />
            )}
          </div>
        </main>
      </div>

      {selectedFinding && (
        <FindingDetail
          finding={selectedFinding}
          scanId={scanResult?.scan_id}
          onClose={handleCloseModal}
          onRemediation={handleRemediation}
        />
      )}

      {remediation && (
        <RemediationView
          remediation={remediation}
          scanId={scanResult?.scan_id}
          onClose={handleCloseModal}
          onVerified={handleVerified}
        />
      )}
      
      {comparison && (
        <BeforeAfter
          comparison={comparison}
          onClose={handleCloseModal}
        />
      )}

      {notification && (
        <div style={{
          position: 'fixed',
          bottom: '2rem',
          right: '2rem',
          backgroundColor: 'var(--surface)',
          border: '1px solid var(--border)',
          padding: '1rem 1.25rem',
          borderRadius: 'var(--radius)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          zIndex: 1000,
          animation: 'fadeIn 0.2s ease-out'
        }}>
          <CheckCircle size={18} color="var(--success)" />
          <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{notification}</span>
        </div>
      )}
    </div>
  );
}

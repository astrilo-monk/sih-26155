import { useState } from 'react';
import { apiClient } from './api/client';
import Header from './components/Header';
import UploadZone from './components/UploadZone';
import LoadingSpinner from './components/LoadingSpinner';
import ScoreGauge from './components/ScoreGauge';
import SeverityCards from './components/SeverityCards';
import DeviceInfo from './components/DeviceInfo';
import FindingsTable from './components/FindingsTable';
import FindingDetail from './components/FindingDetail';
import RemediationView from './components/RemediationView';
import BeforeAfter from './components/BeforeAfter';

export default function App() {
  // View state
  const [view, setView] = useState('upload'); // upload | loading | dashboard
  const [error, setError] = useState(null);

  // Scan data
  const [scanResult, setScanResult] = useState(null);

  // Modal state
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [comparison, setComparison] = useState(null);

  const handleUpload = async (files) => {
    setView('loading');
    setError(null);
    try {
      const result = await apiClient.scanConfigs(files);
      setScanResult(result);
      setView('dashboard');
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

  return (
    <div className="app-container">
      <Header
        showNewScan={view === 'dashboard'}
        onNewScan={handleNewScan}
        timestamp={scanResult?.timestamp}
      />

      <main className="main-content">
        {error && (
          <div style={{
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '0.5rem',
            padding: '1rem 1.5rem',
            color: 'var(--critical)',
            marginBottom: '1.5rem',
          }}>
            ⚠️ {error}
          </div>
        )}

        {view === 'upload' && <UploadZone onUpload={handleUpload} />}

        {view === 'loading' && <LoadingSpinner />}

        {view === 'dashboard' && scanResult && (
          <div className="dashboard-grid">
            <ScoreGauge score={scanResult.score} />
            <SeverityCards
              critical={scanResult.critical}
              high={scanResult.high}
              medium={scanResult.medium}
              low={scanResult.low}
            />
            <DeviceInfo devices={scanResult.devices} />
            <FindingsTable
              findings={scanResult.findings}
              onSelectFinding={handleSelectFinding}
            />
          </div>
        )}
      </main>

      {/* Modals */}
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
    </div>
  );
}

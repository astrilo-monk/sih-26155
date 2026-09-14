import { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle } from 'lucide-react';
import { apiClient } from './api/client';

import Sidebar from './components/Sidebar';
import Header from './components/Header';
import UploadZone from './components/UploadZone';
import ScoreOverview from './components/ScoreOverview';
import DeviceInfo from './components/DeviceInfo';
import FindingsTable from './components/FindingsTable';
import ProvisionalResults, { PROVISIONAL_ASSURANCE } from './components/ProvisionalResults';
import FindingDetail from './components/FindingDetail';
import RemediationView from './components/RemediationView';
import RemediationQueue from './components/RemediationQueue';
import HistoryView from './components/HistoryView';
import AnalysisPath from './components/AnalysisPath';
import FrameworkView from './components/FrameworkView';
import AdaptiveTraining from './components/AdaptiveTraining';
import { markScansExpired, saveScanToHistory } from './utils/history';

// Views that show one scan: without a loaded scan they explain why they are empty
const SCAN_VIEWS = new Set(['dashboard', 'devices', 'findings', 'frameworks', 'remediation', 'training']);
const EXPIRED_MESSAGE = 'This scan is no longer held by the backend (scan results are kept in memory and cleared on restart). Upload the configuration again.';

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
    'Detecting vendor and checking parse coverage',
    'Parsing or tokenizing the configuration',
    'Extracting security facts',
    'Evaluating every control',
    'Calculating posture and coverage'
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

function NoScan({ onNewScan }) {
  return (
    <div className="empty-state">
      <div style={{ marginBottom: '1rem' }}>No scan loaded. Upload a configuration to begin.</div>
      <button className="btn-primary" onClick={onNewScan}>Upload a configuration</button>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState('upload'); // upload | loading | dashboard | devices | findings | frameworks | remediation | training | history
  const [error, setError] = useState(null);
  const [scanResult, setScanResult] = useState(null);

  const [selectedFinding, setSelectedFinding] = useState(null);
  const [remediation, setRemediation] = useState(null);
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
    setError(null);
  };

  const handleSelectFinding = (finding) => {
    setSelectedFinding(finding);
    setRemediation(null);
  };

  const handleRemediation = (rem) => {
    setSelectedFinding(null);
    setRemediation(rem);
  };

  const handleCloseModal = () => {
    setSelectedFinding(null);
    setRemediation(null);
  };

  // The backend no longer holds these scans (restart): never keep showing one as the current scan
  const handleScansExpired = (ids) => {
    markScansExpired(ids);
    setScanResult((current) => {
      if (!current || !ids.includes(current.scan_id)) return current;
      setSelectedFinding(null);
      setRemediation(null);
      setError(EXPIRED_MESSAGE);
      return null;
    });
  };

  const handleSelectHistoryEntry = async (scanId) => {
    setError(null);
    try {
      setScanResult(await apiClient.getScan(scanId));
      setSelectedFinding(null);
      setRemediation(null);
      setView('dashboard');
    } catch (err) {
      if (err.status === 404) {
        handleScansExpired([scanId]);
        setError(EXPIRED_MESSAGE);
      } else {
        setError(`Could not open the scan: ${err.message}`);
      }
    }
  };

  const adaptiveConfigs = scanResult?.adaptive_configs || [];
  const pendingReview = adaptiveConfigs.reduce((sum, c) => sum + (c.pending_review || 0), 0);
  const aiUnavailable = adaptiveConfigs.some((c) => (c.ai_unavailable_lines || 0) > 0);
  const identifications = scanResult?.vendor_identification || [];
  const vendorUnverified = identifications.some((v) => v.status === 'unverified');
  const genericConfigs = identifications.filter((v) => v.status !== 'confirmed').length;
  // Heuristic / AI verdicts awaiting confirmation (one per control per config) plus legacy review lines
  const provisionalControls = new Set((scanResult?.results || [])
    .filter((r) => PROVISIONAL_ASSURANCE.has(r.assurance) || r.proposed_status)
    .map((r) => `${r.config_index}-${r.control_id}`)).size;
  const reviewCount = provisionalControls + pendingReview;
  // Suspected (heuristic / AI) findings are listed but never counted as decided severities
  const decisiveCount = (severity) => (scanResult?.findings || [])
    .filter((f) => f.severity === severity && !PROVISIONAL_ASSURANCE.has(f.assurance)).length;
  const expire = (scanId) => handleScansExpired([scanId]);

  return (
    <div className="app-layout">
      <Sidebar view={view} setView={setView} reviewCount={reviewCount} />

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

            {view === 'upload' && <UploadZone key="upload" onUpload={handleUpload} />}

            {view === 'loading' && <LoadingState />}

            {SCAN_VIEWS.has(view) && !scanResult && <NoScan onNewScan={handleNewScan} />}

            {view === 'dashboard' && scanResult && (
              <>
                {(scanResult.posture == null || genericConfigs > 0 || reviewCount > 0 || aiUnavailable) && (
                  <div style={{ backgroundColor: 'var(--medium-bg)', border: '1px solid var(--medium-border)', padding: '0.75rem 1rem', borderRadius: 'var(--radius)', color: 'var(--medium)', display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.8125rem' }}>
                    <AlertCircle size={16} />
                    <span style={{ flex: 1 }}>
                      {scanResult.posture == null
                        ? 'Not assessed: no control could be decided from confirmed evidence, so no posture was calculated.'
                        : genericConfigs > 0
                          ? `${genericConfigs} configuration(s) had no dedicated parser: their heuristic and AI verdicts are provisional and are not counted in posture or coverage.`
                          : 'Some results are provisional and are not counted in posture or coverage.'}
                      {vendorUnverified && ' A configuration resembles a supported vendor, but its syntax could not be verified.'}
                      {aiUnavailable && ' AI interpretation was unavailable for some lines.'}
                      {reviewCount > 0 && ` ${reviewCount} item(s) await review.`}
                    </span>
                    <button className="btn-secondary" onClick={() => setView('training')}>Review</button>
                  </div>
                )}
                <ScoreOverview
                  score={scanResult.posture}
                  coverage={scanResult.coverage}
                  bounds={scanResult.posture_bounds}
                  criticalUnassessed={scanResult.critical_unassessed}
                  critical={decisiveCount('critical')}
                  high={decisiveCount('high')}
                  medium={decisiveCount('medium')}
                  low={decisiveCount('low')}
                />

                <AnalysisPath scanResult={scanResult} />

                <ProvisionalResults results={scanResult.results} />

                <FindingsTable
                  findings={scanResult.findings}
                  devices={scanResult.devices}
                  onSelectFinding={handleSelectFinding}
                />
              </>
            )}

            {view === 'devices' && scanResult && (
              <DeviceInfo scanResult={scanResult} />
            )}

            {view === 'findings' && scanResult && (
              <FindingsTable
                findings={scanResult.findings}
                devices={scanResult.devices}
                onSelectFinding={handleSelectFinding}
              />
            )}

            {view === 'frameworks' && scanResult && (
              <FrameworkView key={scanResult.scan_id} frameworks={scanResult.frameworks} />
            )}

            {view === 'remediation' && scanResult && (
              <RemediationQueue scanResult={scanResult} onScanExpired={expire} />
            )}

            {view === 'training' && scanResult && (
              <AdaptiveTraining scanResult={scanResult} onScanUpdated={setScanResult} onScanExpired={expire} />
            )}

            {view === 'history' && (
              <HistoryView onSelectHistoryEntry={handleSelectHistoryEntry} onScansExpired={handleScansExpired} />
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
          onClose={handleCloseModal}
          onOpenQueue={() => { handleCloseModal(); setView('remediation'); }}
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

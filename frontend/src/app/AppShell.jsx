import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import { markScansExpired, saveScanToHistory } from '../utils/history';
import { navigate } from '../lib/hooks';
import Upload from './Upload';
import Results, { RESULT_TABS } from './Results';
import History from './History';
import Recognizers from './Recognizers';
import '../styles/app.css';

export function parseAppPath(path) {
  const parts = path.split('/').filter(Boolean);
  if (parts[1] === 'scan' && parts[2]) {
    return { page: 'scan', scanId: decodeURIComponent(parts[2]), tab: RESULT_TABS.includes(parts[3]) ? parts[3] : 'summary' };
  }
  if (parts[1] === 'history') return { page: 'history' };
  if (parts[1] === 'recognizers') return { page: 'recognizers' };
  return { page: 'new' };
}

function ScanUnavailable({ opening, openError }) {
  if (openError?.expired) {
    return (
      <div className="wrap unavailable enter">
        <p className="eyebrow">Audit unavailable</p>
        <h1 className="display page-title">This audit is no longer held by the backend.</h1>
        <p className="lede">Scan results live in backend memory and are cleared when it restarts. Nothing from the
          configuration was kept in this browser — upload it again to re-run the audit.</p>
        <div className="unavailable-actions">
          <a className="btn btn-accent" href="#/app">New audit</a>
          <a className="btn" href="#/app/history">History</a>
        </div>
      </div>
    );
  }
  if (openError) {
    return (
      <div className="wrap unavailable enter">
        <div className="notice notice-danger" role="alert">
          <span className="notice-mark">×</span>
          <strong>The audit could not be opened.</strong>
          <span>{openError.message}</span>
        </div>
      </div>
    );
  }
  return <div className="wrap unavailable" aria-busy={opening}><p className="muted">Opening audit…</p></div>;
}

export default function AppShell({ path }) {
  const route = parseAppPath(path);
  const [scan, setScan] = useState(null);
  // Bumped whenever the scan is replaced or re-evaluated: plans generated for an older state are regenerated
  const [revision, setRevision] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState(null);

  const routeScanId = route.page === 'scan' ? route.scanId : null;

  useEffect(() => {
    if (!routeScanId || scan?.scan_id === routeScanId) return undefined;
    let active = true;
    setOpening(true);
    setOpenError(null);
    apiClient.getScan(routeScanId)
      .then((result) => {
        if (!active) return;
        setScan(result);
        setRevision((r) => r + 1);
      })
      .catch((err) => {
        if (!active) return;
        if (err.status === 404) {
          markScansExpired([routeScanId]);
          setOpenError({ scanId: routeScanId, expired: true });
        } else {
          setOpenError({ scanId: routeScanId, message: err.message });
        }
      })
      .finally(() => { if (active) setOpening(false); });
    return () => { active = false; };
    // the loaded scan is read, not tracked: a scan cleared by expiry must not be refetched in a loop
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeScanId]);

  const handleScan = async (files) => {
    setScanning(true);
    setUploadError(null);
    try {
      const result = await apiClient.scanConfigs(files);
      setScan(result);
      setRevision((r) => r + 1);
      setOpenError(null);
      saveScanToHistory(result);
      navigate(`/app/scan/${result.scan_id}/summary`);
    } catch (err) {
      setUploadError(err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleScanUpdated = (next) => {
    setScan(next);
    setRevision((r) => r + 1);
  };

  // The backend no longer holds these scans (restart): never keep showing one as the current audit
  const handleScansExpired = (ids) => {
    markScansExpired(ids);
    setScan((current) => (current && ids.includes(current.scan_id) ? null : current));
    if (routeScanId && ids.includes(routeScanId)) setOpenError({ scanId: routeScanId, expired: true });
  };

  const current = (page) => (route.page === page ? 'page' : undefined);

  return (
    <div className="app">
      <button type="button" className="skip-link" onClick={() => document.getElementById('main')?.focus()}>Skip to content</button>
      <header className="appbar">
        <div className="appbar-inner">
          <a className="brand" href="#/" aria-label="NetAuditAI home">
            <span className="brand-mark" aria-hidden="true"><span /></span>
            <span className="brand-name">NetAudit<span>AI</span></span>
          </a>
          <nav aria-label="Application" className="appnav">
            <a href="#/app" aria-current={current('new')}>New audit</a>
            {scan && <a href={`#/app/scan/${scan.scan_id}/summary`} aria-current={current('scan')}>Current audit</a>}
            <a href="#/app/history" aria-current={current('history')}>History</a>
            <a href="#/app/recognizers" aria-current={current('recognizers')}>Recognizers</a>
          </nav>
        </div>
      </header>

      <main id="main" tabIndex={-1} className="app-main">
        {route.page === 'new' && (
          <Upload onScan={handleScan} scanning={scanning} error={uploadError} currentScan={scan} />
        )}
        {route.page === 'scan' && (scan && scan.scan_id === routeScanId ? (
          <Results
            key={scan.scan_id}
            scan={scan}
            tab={route.tab}
            revision={revision}
            onScanUpdated={handleScanUpdated}
            onScanExpired={(id) => handleScansExpired([id])}
          />
        ) : (
          <ScanUnavailable opening={opening} openError={openError?.scanId === routeScanId ? openError : null} />
        ))}
        {route.page === 'history' && (
          <History onScansExpired={handleScansExpired} />
        )}
        {route.page === 'recognizers' && <Recognizers />}
      </main>
    </div>
  );
}

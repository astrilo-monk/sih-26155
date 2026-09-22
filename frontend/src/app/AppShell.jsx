import { useCallback, useEffect, useState } from 'react';
import { Notice } from '../components/ui/primitives';
import { apiClient } from '../api/client';
import { markScansExpired, saveScanToHistory } from '../utils/history';
import { navigate } from '../lib/hooks';
import { useAudit } from '../lib/useAudit';
import { auditCounts, checkItems, deviceLabels } from '../lib/domain';
import Upload from './Upload';
import Results from './Results';
import Fix from './Fix';
import Teach from './Teach';
import Checks from './Checks';
import Devices from './Devices';
import Frameworks from './Frameworks';
import History from './History';
import Learned from './Learned';
import FindingDrawer from './FindingDrawer';
import LearningFlow from './LearningFlow';
import '../styles/app.css';

export const SCAN_VIEWS = ['overview', 'fix', 'teach', 'checks', 'devices', 'frameworks'];
// Links from earlier versions keep working
const OLD_VIEWS = { summary: 'overview', findings: 'checks', review: 'teach', remediation: 'fix' };

export function parseAppPath(path) {
  const parts = path.split('/').filter(Boolean);
  if (parts[1] === 'scan' && parts[2]) {
    const view = OLD_VIEWS[parts[3]] || (SCAN_VIEWS.includes(parts[3]) ? parts[3] : 'overview');
    return { page: 'scan', scanId: decodeURIComponent(parts[2]), view };
  }
  if (parts[1] === 'history') return { page: 'history' };
  if (parts[1] === 'learned' || parts[1] === 'recognizers') return { page: 'learned' };
  return { page: 'new' };
}

function ScanUnavailable({ opening, openError }) {
  if (openError?.expired) {
    return (
      <div className="wrap empty-state enter">
        <h1 className="page-title">This scan is no longer available.</h1>
        <p className="lede">Scan results are kept only until the backend restarts. Nothing from the configuration was kept in this browser -upload it again to scan it.</p>
        <div className="actions">
          <a className="btn btn-primary" href="#/app">Scan again</a>
          <a className="btn" href="#/app/history">History</a>
        </div>
      </div>
    );
  }
  if (openError) {
    return (
      <div className="wrap">
        <Notice kind="danger" label="Couldn’t open" role="alert">
          <strong>The scan could not be opened.</strong>
          <span>{openError.message}</span>
        </Notice>
      </div>
    );
  }
  return <div className="wrap" aria-busy={opening}><p className="muted">Opening scan…</p></div>;
}

export default function AppShell({ path }) {
  const route = parseAppPath(path);
  const [scan, setScan] = useState(null);
  // Bumped whenever the scan is replaced or re-evaluated: the plan and review queue are fetched again
  const [revision, setRevision] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState(null);
  const [openKey, setOpenKey] = useState(null);
  const [teachFocus, setTeachFocus] = useState(null);

  const routeScanId = route.page === 'scan' ? route.scanId : null;

  // The backend no longer holds these scans (restart): never keep showing one as the current scan
  const handleScansExpired = useCallback((ids) => {
    markScansExpired(ids);
    setScan((current) => (current && ids.includes(current.scan_id) ? null : current));
    if (routeScanId && ids.includes(routeScanId)) setOpenError({ scanId: routeScanId, expired: true });
  }, [routeScanId]);

  const audit = useAudit(scan, revision, (id) => handleScansExpired([id]));

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

  // A drawer belongs to the page it was opened on
  useEffect(() => { setOpenKey(null); }, [path]);

  const handleScan = async (files) => {
    setScanning(true);
    setUploadError(null);
    try {
      const result = await apiClient.scanConfigs(files);
      setScan(result);
      setRevision((r) => r + 1);
      setOpenError(null);
      saveScanToHistory(result);
      navigate(`/app/scan/${result.scan_id}`);
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

  const current = scan && scan.scan_id === routeScanId ? scan : null;
  const base = scan ? `/app/scan/${scan.scan_id}` : null;
  const go = (view) => navigate(view === 'overview' ? base : `${base}/${view}`);
  const openTeach = (focus = null) => {
    setTeachFocus(focus);
    setOpenKey(null);
    go('teach');
  };
  const labels = current ? deviceLabels(current.devices) : [];
  const counts = current ? auditCounts(current, audit.plan, audit.applied, audit.queue) : null;
  const openItem = current && openKey ? checkItems(current, audit.plan).find((i) => i.key === openKey) : null;
  const here = (page, view) => (route.page === page && (!view || route.view === view) ? 'page' : undefined);
  const closeDrawer = useCallback(() => setOpenKey(null), []);
  const shared = { scan: current, audit, labels, onOpen: (item) => setOpenKey(item.key) };

  const scanHref = (view) => (scan ? `#${view === 'overview' ? base : `${base}/${view}`}` : null);
  // Adaptive learning is this scan's questions when a scan is open, otherwise what has been learned so far
  const learning = route.page === 'learned' || here('scan', 'teach');
  const NAV = [
    ['New scan', '#/app', here('new')],
    ['Overview', scanHref('overview'), here('scan', 'overview')],
    ['Devices', scanHref('devices'), here('scan', 'devices')],
    ['Findings', scanHref('checks'), here('scan', 'checks')],
    // every problem still open, so the badge cannot contradict the problem count on Results
    ['Remediation', scanHref('fix'), here('scan', 'fix'), counts && counts.problems - counts.fixed],
  ];
  const INTEL = [
    ['Adaptive learning', scan ? scanHref('teach') : '#/app/learned', learning ? 'page' : undefined, counts?.review],
    ['Frameworks', scanHref('frameworks'), here('scan', 'frameworks')],
    ['History', '#/app/history', here('history')],
  ];
  const navItem = ([label, href, current, n]) => (
    <li key={label}>
      {href ? (
        <a href={href} aria-current={current}>
          <span>{label}</span>{n > 0 && <span className="side-n tnum" aria-label={`, ${n} waiting`}>{n}</span>}
        </a>
      ) : (
        <span className="side-off" aria-disabled="true" title="Run a scan first">{label}</span>
      )}
    </li>
  );

  return (
    <div className="app">
      <button type="button" className="skip-link" onClick={() => document.getElementById('main')?.focus()}>Skip to content</button>
      <aside className="sidebar">
        <a className="brand side-brand" href="#/" aria-label="NetAuditAI home">
          <span className="brand-mark" aria-hidden="true"><span /></span>
          <span className="brand-name">NetAudit<span>AI</span></span>
        </a>
        <nav aria-label="Main" className="side-nav">
          <ul>{NAV.map(navItem)}</ul>
          <p className="side-k">Intelligence</p>
          <ul>{INTEL.map(navItem)}</ul>
        </nav>
      </aside>

      <div className="app-body">
        <header className="appbar">
          <p className="appbar-title">Network security configuration analyzer</p>
          <a className="btn btn-sm btn-outline" href="#/">Exit</a>
        </header>

      <main id="main" tabIndex={-1} className="app-main" key={route.page === 'scan' ? route.view : route.page}>
        {route.page === 'new' && <Upload onScan={handleScan} scanning={scanning} error={uploadError} currentScan={scan} />}
        {route.page === 'scan' && (current ? (
          <>
            {route.view === 'overview' && <Results {...shared} go={go} onTeach={openTeach} />}
            {route.view === 'fix' && <Fix {...shared} onTeach={() => openTeach()} />}
            {route.view === 'teach' && <LearningFlow scanHref={scanHref('teach')} here="teach" />}
            {route.view === 'teach' && (
              <Teach scan={current} audit={audit} focusKey={teachFocus} onScanUpdated={handleScanUpdated}
                     onScanExpired={(id) => handleScansExpired([id])} />
            )}
            {route.view === 'checks' && <Checks {...shared} />}
            {route.view === 'devices' && <Devices scan={current} audit={audit} />}
            {route.view === 'frameworks' && (
              <div className="wrap enter">
                <header className="page-head">
                  <p className="eyebrow">Frameworks</p>
                  <h1 className="page-title">The same results, by framework requirement</h1>
                </header>
                <Frameworks key={`fw-${revision}`} frameworks={current.frameworks || []} />
              </div>
            )}
          </>
        ) : (
          <ScanUnavailable opening={opening} openError={openError?.scanId === routeScanId ? openError : null} />
        ))}
        {route.page === 'history' && <History onScansExpired={handleScansExpired} />}
        {route.page === 'learned' && <LearningFlow scanHref={scanHref('teach')} here="learned" />}
        {route.page === 'learned' && <Learned />}
      </main>
      </div>

      {openItem && (
        <FindingDrawer item={openItem} scan={current} audit={audit} labels={labels} onClose={closeDrawer} onTeach={() => openTeach(openItem.key)} />
      )}
    </div>
  );
}

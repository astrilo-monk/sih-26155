import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import { Notice } from '../components/ui/primitives';

// A device row is only complete once it has somewhere to connect and something to connect as
const ready = (d) => d.host.trim() && d.platform && d.username.trim();

const blank = (platform = '') => ({
  host: '', platform, username: '', password: '', port: 22, enable: '', method: 'auto',
});

export default function Collect({ onCollect, framework, currentScan }) {
  const [caps, setCaps] = useState(null);
  const [capsError, setCapsError] = useState(null);
  const [devices, setDevices] = useState([blank()]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiClient.getCollectCapabilities().then(setCaps).catch((e) => setCapsError(e.message));
  }, []);

  const set = (i, patch) => setDevices((prev) => prev.map((d, j) => (j === i ? { ...d, ...patch } : d)));

  const platforms = caps?.platforms || [];
  const usable = platforms.filter((p) => p.available);
  const complete = devices.filter(ready);

  const submit = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await onCollect(complete.map((d) => ({ ...d, port: Number(d.port) || 22 })), framework);
      // Only a partial collection comes back here: a clean one navigates to its results
      if (res) setResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
      // Credentials are for one request. Nothing in this browser keeps them afterwards.
      setDevices((prev) => prev.map((d) => ({ ...d, password: '', enable: '' })));
    }
  };

  if (capsError) {
    return (
      <Notice kind="danger" label="Unavailable" role="alert">
        <strong>The backend could not be asked about live collection.</strong>
        <span>{capsError}</span>
      </Notice>
    );
  }

  if (!caps) return <p className="small muted">Checking what this backend can collect…</p>;

  if (!caps.enabled) {
    return (
      <Notice kind="info" label="Disabled">
        <strong>Live collection is switched off on this backend.</strong>
        <span>
          It is on by default, so someone turned it off here -it opens an SSH session to every device
          it is given, which is worth closing on a backend others can reach. Set{' '}
          <span className="mono">LIVE_COLLECTION_ENABLED=true</span> to turn it back on. Until then,
          upload configuration files instead.
        </span>
      </Notice>
    );
  }

  if (!usable.length) {
    return (
      <Notice kind="warning" label="No drivers">
        <strong>Neither Netmiko nor NAPALM is installed.</strong>
        <span>
          Collection is enabled but has nothing to connect with. Netmiko is a normal dependency, so
          this install is incomplete: run{' '}
          <span className="mono">pip install -r requirements.txt</span> in the backend.
        </span>
      </Notice>
    );
  }

  return (
    <div className="collect-panel">
      {error && (
        <Notice kind="danger" label="Collection failed" role="alert">
          <strong>Nothing could be collected.</strong>
          <span>{error}</span>
        </Notice>
      )}

      {result?.failures?.length > 0 && (
        <Notice kind="warning" label="Partly collected" role="alert">
          <strong>
            {result.collected.length} of {result.collected.length + result.failures.length} devices
            were read. The others were not, so they are absent from this audit rather than passing it.
          </strong>
          <ul className="aside-list">
            {result.failures.map((f) => (
              <li key={f.host}><span className="mono">{f.host}</span> -{f.error}</li>
            ))}
          </ul>
          {result.scan && (
            <span><a href={`#/app/scan/${result.scan.scan_id}`}>View the results for the devices that answered</a>.</span>
          )}
        </Notice>
      )}

      <Notice kind="info" label="Credentials">
        <strong>Credentials are used for this one request and never stored.</strong>
        <span>
          The backend opens a session, reads the configuration and closes it. Nothing is written to
          the scan, the archive or the logs, and this page clears the password fields as soon as the
          request finishes. Use a read-only account wherever the platform offers one.
        </span>
      </Notice>

      {devices.map((device, i) => (
        <fieldset className="collect-device" key={i}>
          <legend className="eyebrow">Device {String(i + 1).padStart(2, '0')}</legend>

          <div className="collect-grid">
            <label className="field">
              <span className="field-label">Host</span>
              <input className="input mono" value={device.host} placeholder="10.0.0.1"
                     autoComplete="off"
                     onChange={(e) => set(i, { host: e.target.value })} />
            </label>

            <label className="field">
              <span className="field-label">Platform</span>
              <select className="select" value={device.platform}
                      onChange={(e) => set(i, { platform: e.target.value })}>
                <option value="">Choose a platform…</option>
                {usable.map((p) => <option key={p.platform} value={p.platform}>{p.label}</option>)}
              </select>
              <span className="field-help">
                {device.platform
                  ? `Reads it with: ${platforms.find((p) => p.platform === device.platform)?.command}`
                  : 'The platform decides which command reads the configuration.'}
              </span>
            </label>

            <label className="field">
              <span className="field-label">Username</span>
              <input className="input mono" value={device.username} autoComplete="off"
                     onChange={(e) => set(i, { username: e.target.value })} />
            </label>

            <label className="field">
              <span className="field-label">Password</span>
              <input className="input" type="password" value={device.password} autoComplete="new-password"
                     onChange={(e) => set(i, { password: e.target.value })} />
            </label>

            <label className="field">
              <span className="field-label">Port</span>
              <input className="input mono" type="number" min="1" max="65535" value={device.port}
                     onChange={(e) => set(i, { port: e.target.value })} />
            </label>

            <label className="field">
              <span className="field-label">Enable secret</span>
              <input className="input" type="password" value={device.enable} autoComplete="new-password"
                     onChange={(e) => set(i, { enable: e.target.value })} />
              <span className="field-help">Optional. Only where the platform needs it to print its configuration.</span>
            </label>

            <label className="field">
              <span className="field-label">Driver</span>
              <select className="select" value={device.method}
                      onChange={(e) => set(i, { method: e.target.value })}>
                <option value="auto">Automatic</option>
                {caps.methods.map((m) => <option key={m} value={m}>{m === 'napalm' ? 'NAPALM' : 'Netmiko'}</option>)}
              </select>
              <span className="field-help">Automatic prefers NAPALM where it has a driver, and falls back to Netmiko.</span>
            </label>
          </div>

          {devices.length > 1 && (
            <button type="button" className="btn btn-quiet btn-sm"
                    onClick={() => setDevices((prev) => prev.filter((_, j) => j !== i))}>
              Remove device
            </button>
          )}
        </fieldset>
      ))}

      <div className="upload-actions">
        <button type="button" className="btn btn-quiet"
                onClick={() => setDevices((prev) => [...prev, blank(prev[prev.length - 1]?.platform || '')])}>
          Add another device
        </button>
        <button type="button" className="btn btn-accent btn-lg" disabled={!complete.length || busy}
                onClick={submit}>
          {busy ? 'Collecting…' : 'Collect and scan'}
        </button>
        <span className="small muted">
          {complete.length
            ? `${complete.length} device${complete.length > 1 ? 's' : ''} will be collected and scanned together.`
            : 'Give each device a host, a platform and a username.'}
        </span>
      </div>

      {currentScan && (
        <p className="small muted">Or <a href={`#/app/scan/${currentScan.scan_id}`}>return to the current scan</a>.</p>
      )}
    </div>
  );
}

import { Shield, LayoutDashboard, Search, Server, AlertCircle, Wrench, Settings, Activity } from 'lucide-react';

export default function Sidebar({ view, setView, devices }) {
  const navItems = [
    { id: 'upload', label: 'New Scan', icon: Search },
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'devices', label: 'Devices', icon: Server },
    { id: 'findings', label: 'Findings', icon: AlertCircle },
    { id: 'remediation', label: 'Remediation', icon: Wrench },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <Shield size={20} color="var(--text-primary)" />
        NetAuditAI
      </div>
      <div className="sidebar-nav">
        {navItems.map((item) => (
          <div key={item.id}>
            <button
              className={`nav-item ${view === item.id || (view === 'loading' && item.id === 'upload') ? 'active' : ''}`}
              onClick={() => setView(item.id === 'upload' ? 'upload' : 'dashboard')}
              style={{ width: '100%', justifyContent: 'flex-start' }}
            >
              <item.icon size={16} />
              {item.label}
            </button>
            {item.id === 'devices' && devices && devices.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem', paddingLeft: '2.5rem' }}>
                {devices.map((d, i) => (
                  <div key={i} style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {d.hostname}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
          <Activity size={12} color="var(--success)" />
          Engine Online
        </div>
        v2.4.1-stable
      </div>
    </aside>
  );
}

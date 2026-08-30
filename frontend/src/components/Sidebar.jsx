import { Shield, LayoutDashboard, Search, Server, AlertCircle, Wrench, Settings, Activity } from 'lucide-react';

export default function Sidebar({ view, setView }) {
  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'upload', label: 'New Scan', icon: Search },
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
          <button
            key={item.id}
            className={`nav-item ${view === item.id || (view === 'loading' && item.id === 'upload') ? 'active' : ''}`}
            onClick={() => setView(item.id === 'upload' ? 'upload' : 'dashboard')}
          >
            <item.icon size={16} />
            {item.label}
          </button>
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

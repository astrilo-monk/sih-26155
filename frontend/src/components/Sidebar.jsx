import { Shield, LayoutDashboard, Search, Server, AlertCircle, History, Wrench, GraduationCap, ListChecks } from 'lucide-react';

export default function Sidebar({ view, setView, devices, pendingReview = 0 }) {
  const navItems = [
    { id: 'upload', label: 'New Scan', icon: Search },
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'devices', label: 'Devices', icon: Server },
    { id: 'findings', label: 'Findings', icon: AlertCircle },
    { id: 'frameworks', label: 'Frameworks', icon: ListChecks },
    { id: 'remediation', label: 'Remediation', icon: Wrench },
    { id: 'training', label: 'Review & Recognizers', icon: GraduationCap, count: pendingReview },
    { id: 'history', label: 'History', icon: History },
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
              onClick={() => setView(item.id)}
              style={{ width: '100%', justifyContent: 'flex-start' }}
            >
              <item.icon size={16} />
              {item.label}
              {item.count > 0 && (
                <span className="badge medium" style={{ marginLeft: 'auto' }}>{item.count}</span>
              )}
            </button>
          </div>
        ))}
      </div>
      <div className="sidebar-footer">
        v2.4.1-stable
      </div>
    </aside>
  );
}

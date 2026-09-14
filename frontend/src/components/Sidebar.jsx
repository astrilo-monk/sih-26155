import { Shield, LayoutDashboard, Search, Server, AlertCircle, History, Wrench, GraduationCap, ListChecks } from 'lucide-react';
import pkg from '../../package.json';

export default function Sidebar({ view, setView, reviewCount = 0 }) {
  const navItems = [
    { id: 'upload', label: 'New Scan', icon: Search },
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'devices', label: 'Devices', icon: Server },
    { id: 'findings', label: 'Findings', icon: AlertCircle },
    { id: 'frameworks', label: 'Frameworks', icon: ListChecks },
    { id: 'remediation', label: 'Remediation', icon: Wrench },
    { id: 'training', label: 'Review & Recognizers', icon: GraduationCap, count: reviewCount },
    { id: 'history', label: 'History', icon: History },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <Shield size={20} color="var(--text-primary)" />
        NetAuditAI
      </div>
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${view === item.id || (view === 'loading' && item.id === 'upload') ? 'active' : ''}`}
            onClick={() => setView(item.id)}
            title={item.count > 0 ? `${item.count} provisional result(s) or line(s) await review` : undefined}
          >
            <item.icon size={16} />
            {item.label}
            {item.count > 0 && (
              <span className="badge medium" style={{ marginLeft: 'auto' }}>{item.count}</span>
            )}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        v{pkg.version}
      </div>
    </aside>
  );
}

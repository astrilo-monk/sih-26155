export default function SeverityCards({ critical, high, medium, low }) {
  const cards = [
    { label: 'Critical', count: critical, colorClass: 'critical-color', icon: '🔴' },
    { label: 'High', count: high, colorClass: 'high-color', icon: '🟠' },
    { label: 'Medium', count: medium, colorClass: 'medium-color', icon: '🟡' },
    { label: 'Low', count: low, colorClass: 'low-color', icon: '🟢' },
  ];

  return (
    <div className="severity-row">
      {cards.map(({ label, count, colorClass, icon }) => (
        <div className="severity-card" key={label}>
          <div className="severity-header">
            <span>{label}</span>
            <span>{icon}</span>
          </div>
          <div className={`severity-count ${colorClass}`}>{count}</div>
        </div>
      ))}
    </div>
  );
}

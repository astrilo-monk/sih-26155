import { useState, useEffect, useRef } from 'react';

export default function ScoreGauge({ score }) {
  const [displayScore, setDisplayScore] = useState(0);
  const radius = 85;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (displayScore / 100) * circumference;

  const getColor = (s) => {
    if (s < 40) return 'var(--critical)';
    if (s < 70) return 'var(--high)';
    if (s < 85) return 'var(--medium)';
    return 'var(--low)';
  };

  // Animate the score counting up
  useEffect(() => {
    let start = 0;
    const duration = 1200;
    const startTime = performance.now();

    function animate(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(Math.round(eased * score));
      if (progress < 1) requestAnimationFrame(animate);
    }

    requestAnimationFrame(animate);
  }, [score]);

  return (
    <div className="score-card">
      <div className="score-gauge-container">
        <svg className="score-svg" viewBox="0 0 200 200">
          <circle
            className="score-circle-bg"
            cx="100" cy="100" r={radius}
          />
          <circle
            className="score-circle-value"
            cx="100" cy="100" r={radius}
            stroke={getColor(displayScore)}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="score-value" style={{ color: getColor(displayScore) }}>
          {displayScore}
          <span className="score-label">Security Score</span>
        </div>
      </div>
    </div>
  );
}

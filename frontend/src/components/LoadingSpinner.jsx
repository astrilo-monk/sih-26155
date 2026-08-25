import React from 'react';

export default function LoadingSpinner({ message = 'Analyzing configuration...' }) {
  return (
    <div className="loading-container">
      <div className="spinner"></div>
      <p style={{ color: 'var(--text-secondary)', marginTop: '1rem' }}>{message}</p>
    </div>
  );
}

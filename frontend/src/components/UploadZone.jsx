import React, { useState, useRef } from 'react';

export default function UploadZone({ onScan }) {
  const [dragActive, setDragActive] = useState(false);
  const [files, setFiles] = useState([]);
  const inputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const newFiles = Array.from(e.dataTransfer.files);
      setFiles((prev) => [...prev, ...newFiles]);
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      const newFiles = Array.from(e.target.files);
      setFiles((prev) => [...prev, ...newFiles]);
    }
  };

  const handleScanClick = () => {
    if (files.length > 0) {
      onScan(files);
    }
  };

  return (
    <div className="upload-container">
      <div 
        className={`upload-card ${dragActive ? 'drag-active' : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <input 
          ref={inputRef}
          type="file" 
          multiple 
          accept=".cfg,.conf,.txt"
          onChange={handleChange} 
          style={{ display: 'none' }} 
        />
        <div className="upload-icon">📁</div>
        <h2 className="upload-title">Upload Network Configurations</h2>
        <p className="upload-subtitle">Drag & drop .cfg, .conf, or .txt files here, or click to browse</p>
        
        {files.length > 0 && (
          <div className="file-list">
            <h3 style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Selected Files ({files.length})</h3>
            {files.map((file, i) => (
              <div key={i} className="file-item">
                📄 <span>{file.name}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {files.length > 0 && (
        <button 
          className="btn-primary" 
          style={{ marginTop: '2rem', padding: '0.75rem 2rem', fontSize: '1.125rem' }}
          onClick={handleScanClick}
        >
          Run Security Scan
        </button>
      )}
    </div>
  );
}

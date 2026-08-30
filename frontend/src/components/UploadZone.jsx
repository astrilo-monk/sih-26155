import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, Play } from 'lucide-react';

export default function UploadZone({ onUpload }) {
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
      onUpload(files);
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
        <UploadCloud className="upload-icon" size={48} />
        <h2 className="upload-title">Upload Network Configurations</h2>
        <p className="upload-subtitle">Drag & drop .cfg, .conf, or .txt files here, or click to browse</p>
        
        {files.length > 0 && (
          <div className="file-list" onClick={(e) => e.stopPropagation()}>
            <div className="section-title">Selected Files ({files.length})</div>
            {files.map((file, i) => (
              <div key={i} className="file-item-upload">
                <FileText size={14} color="var(--text-tertiary)" />
                {file.name}
              </div>
            ))}
          </div>
        )}
      </div>

      {files.length > 0 && (
        <button 
          className="btn-primary" 
          style={{ marginTop: '2rem', padding: '0.75rem 2rem', fontSize: '1rem' }}
          onClick={handleScanClick}
        >
          <Play size={16} />
          Run Security Scan
        </button>
      )}
    </div>
  );
}

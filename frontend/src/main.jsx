import React from 'react'
import ReactDOM from 'react-dom/client'
// Base design system first: page styles imported by components refine it
import './index.css'
import App from './App.jsx'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

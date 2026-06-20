import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './app'
import { LFPMProvider } from './context/LFPMContext'
import './style.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <LFPMProvider>
      <App />
    </LFPMProvider>
  </React.StrictMode>
)

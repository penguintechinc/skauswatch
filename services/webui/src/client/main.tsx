import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { AppConsoleVersion } from '@penguintechinc/react-libs';
import App from './App';
import './index.css';

// Log version information to console
AppConsoleVersion({
  webuiVersion: '1.0.0',
  webuildBuild: Date.now(),
  apiUrl: import.meta.env.VITE_API_URL || '/api/v1',
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);

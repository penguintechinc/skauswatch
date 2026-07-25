import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { EntitlementsProvider } from './context/EntitlementsContext';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <EntitlementsProvider>
        <App />
      </EntitlementsProvider>
    </BrowserRouter>
  </React.StrictMode>
);

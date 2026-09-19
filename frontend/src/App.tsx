import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { DashboardLayout } from './layouts/DashboardLayout';
import { Dashboard } from './pages/Dashboard';
import { NewScan } from './pages/NewScan';
import { Scans } from './pages/Scans';
import { Assets } from './pages/Assets';
import { Reports } from './pages/Reports';
import { AIChat } from './pages/AIChat';
import { KnowledgeBase } from './pages/KnowledgeBase';
import { Settings } from './pages/Settings';
import { ToolHealth } from './pages/ToolHealth';
import { Auth } from './pages/Auth';
import { getToken, clearToken, onUnauthorized, apiFetch } from './api';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return getToken() !== null;
  });

  useEffect(() => {
    onUnauthorized(() => setIsAuthenticated(false));
    return () => onUnauthorized(() => {});
  }, []);

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    const token = getToken();
    clearToken();
    setIsAuthenticated(false);
    if (token) {
      apiFetch('/auth/logout', { method: 'POST' }).catch(() => {});
    }
  };

  if (!isAuthenticated) {
    return <Auth onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <Router>
      <DashboardLayout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/chat" element={<AIChat />} />
          <Route path="/knowledge" element={<KnowledgeBase />} />
          <Route path="/tools" element={<ToolHealth />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </DashboardLayout>
    </Router>
  );
};

export default App;
import React, { useState } from 'react';
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
import { Auth } from './pages/Auth';

const App: React.FC = () => {
  // Simple session authentication hook
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('cyberagent_session') === 'active';
  });

  const handleLoginSuccess = () => {
    localStorage.setItem('cyberagent_session', 'active');
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('cyberagent_session');
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Auth onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <Router>
      <DashboardLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/chat" element={<AIChat />} />
          <Route path="/knowledge" element={<KnowledgeBase />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </DashboardLayout>
    </Router>
  );
};

export default App;

import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAppStore } from './store';

// Components
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Login from './views/Login';
import FleetDashboard from './views/FleetDashboard';
import TerminalView from './views/TerminalView';
import ContainersView from './views/ContainersView';
import AccessView from './views/AccessView';
import SysscriptsView from './views/SysscriptsView';
import AlertsView from './views/AlertsView';

const PrivateRoute = ({ children }) => {
  const isAuthenticated = useAppStore(state => state.isAuthenticated);
  return isAuthenticated ? children : <Navigate to="/login" />;
};

const AppLayout = ({ children }) => (
  <div className="app-container">
    <Sidebar />
    <div className="main-content">
      <Topbar />
      {children}
    </div>
  </div>
);

function App() {
  const isAuthenticated = useAppStore(state => state.isAuthenticated);
  const checkSession = useAppStore(state => state.checkSession);

  // Check for OAuth session on mount
  useEffect(() => {
    checkSession();
  }, [checkSession]);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={!isAuthenticated ? <Login /> : <Navigate to="/" />} />
        
        <Route path="/" element={
          <PrivateRoute>
            <AppLayout>
              <FleetDashboard />
            </AppLayout>
          </PrivateRoute>
        } />
        
        <Route path="/terminal/:hostId" element={
          <PrivateRoute>
            <AppLayout>
              <TerminalView />
            </AppLayout>
          </PrivateRoute>
        } />
        
        <Route path="/containers" element={
          <PrivateRoute>
            <AppLayout>
              <ContainersView />
            </AppLayout>
          </PrivateRoute>
        } />

        <Route path="/access" element={
          <PrivateRoute>
            <AppLayout>
              <AccessView />
            </AppLayout>
          </PrivateRoute>
        } />

        <Route path="/scripts" element={
          <PrivateRoute>
            <AppLayout>
              <SysscriptsView />
            </AppLayout>
          </PrivateRoute>
        } />
        
        <Route path="/alerts" element={
          <PrivateRoute>
            <AppLayout>
              <AlertsView />
            </AppLayout>
          </PrivateRoute>
        } />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

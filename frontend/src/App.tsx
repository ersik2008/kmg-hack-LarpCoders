import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Repositories from './pages/Repositories';
import ScanDetails from './pages/ScanDetails';
import Findings from './pages/Findings';
import Settings from './pages/Settings';
import AttackPaths from './pages/AttackPaths';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        <Route path="/" element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="repositories" element={<Repositories />} />
          <Route path="scans/:id" element={<ScanDetails />} />
          <Route path="attack-paths" element={<AttackPaths />} />
          <Route path="findings" element={<Findings />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;

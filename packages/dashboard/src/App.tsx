import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Agents from './pages/Agents';
import Credentials from './pages/Credentials';
import AuditTrail from './pages/AuditTrail';
import Compliance from './pages/Compliance';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="agents" element={<Agents />} />
        <Route path="credentials" element={<Credentials />} />
        <Route path="audit" element={<AuditTrail />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}

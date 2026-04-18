import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import VLANs from './pages/VLANs';
import AccessSettings from './pages/AccessSettings';
import Users from './pages/Users';
import Vouchers from './pages/Vouchers';
import Roles from './pages/Roles';
import BandwidthProfiles from './pages/BandwidthProfiles';
import Policies from './pages/Policies';
import IdentitySources from './pages/IdentitySources';
import PortalProfiles from './pages/PortalProfiles';
import RadiusClients from './pages/RadiusClients';
import Sessions from './pages/Sessions';
import Alerts from './pages/Alerts';
import ConfigRevisions from './pages/ConfigRevisions';
import Backups from './pages/Backups';
import AIRecommendations from './pages/AIRecommendations';

const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
};

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <PrivateRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/access-settings" element={<AccessSettings />} />
                <Route path="/vlans" element={<VLANs />} />
                <Route path="/portal-profiles" element={<PortalProfiles />} />
                <Route path="/users" element={<Users />} />
                <Route path="/vouchers" element={<Vouchers />} />
                <Route path="/roles" element={<Roles />} />
                <Route path="/bandwidth-profiles" element={<BandwidthProfiles />} />
                <Route path="/policies" element={<Policies />} />
                <Route path="/identity-sources" element={<IdentitySources />} />
                <Route path="/radius-clients" element={<RadiusClients />} />
                <Route path="/sessions" element={<Sessions />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/config-revisions" element={<ConfigRevisions />} />
                <Route path="/backups" element={<Backups />} />
                <Route path="/ai-recommendations" element={<AIRecommendations />} />
              </Routes>
            </Layout>
          </PrivateRoute>
        }
      />
    </Routes>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;

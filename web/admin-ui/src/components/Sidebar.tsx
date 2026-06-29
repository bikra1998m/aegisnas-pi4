import { NavLink } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const navItems = [
  { to: '/', label: 'Dashboard', mark: 'DB', roles: ['super_admin', 'ops_admin', 'guest_admin', 'read_only'] },
  { to: '/access-settings', label: 'Access Settings', mark: 'AS', roles: ['super_admin'] },
  { to: '/admin-principals', label: 'Admin Access', mark: 'AA', roles: ['super_admin'] },
  { to: '/vlans', label: 'VLANs', mark: 'VL', roles: ['super_admin'] },
  { to: '/portal-profiles', label: 'Portal Profiles', mark: 'PP', roles: ['super_admin'] },
  { to: '/users', label: 'Users', mark: 'US', roles: ['super_admin'] },
  { to: '/devices', label: 'Devices', mark: 'DV', roles: ['super_admin', 'ops_admin', 'guest_admin', 'read_only'] },
  { to: '/guest-registrations', label: 'Guest Requests', mark: 'GR', roles: ['super_admin', 'ops_admin', 'guest_admin', 'read_only'] },
  { to: '/vouchers', label: 'Vouchers', mark: 'VO', roles: ['super_admin'] },
  { to: '/roles', label: 'Roles', mark: 'RO', roles: ['super_admin'] },
  { to: '/bandwidth-profiles', label: 'Bandwidth', mark: 'BW', roles: ['super_admin'] },
	{ to: '/policies', label: 'Policies', mark: 'PO', roles: ['super_admin'] },
	{ to: '/acl-policies', label: 'ACL Policies', mark: 'AC', roles: ['super_admin'] },
  { to: '/identity-sources', label: 'Identity Sources', mark: 'ID', roles: ['super_admin'] },
  { to: '/radius-clients', label: 'RADIUS Clients', mark: 'RC', roles: ['super_admin'] },
  { to: '/vendor-compatibility', label: 'Vendor Compatibility', mark: 'VC', roles: ['super_admin', 'ops_admin', 'read_only'] },
  { to: '/sessions', label: 'Sessions', mark: 'SE', roles: ['super_admin', 'ops_admin', 'guest_admin', 'read_only'] },
  { to: '/alerts', label: 'Alerts', mark: 'AL', roles: ['super_admin', 'ops_admin', 'read_only'] },
  { to: '/config-revisions', label: 'Revisions', mark: 'RV', roles: ['super_admin', 'ops_admin'] },
  { to: '/backups', label: 'Backups', mark: 'BK', roles: ['super_admin'] },
  { to: '/ai-recommendations', label: 'AI Insights', mark: 'AI', roles: ['super_admin', 'ops_admin'] },
];

export default function Sidebar() {
  const { identity } = useAuth();
  const role = identity?.role || 'super_admin';
  const visibleItems = navItems.filter((item) => item.roles.includes(role));

  return (
    <div className="flex w-64 flex-col bg-gray-950 text-white">
      <div className="border-b border-gray-800 p-4 text-2xl font-bold">AegisNAS</div>
      <nav className="flex-1 overflow-y-auto py-4">
        {visibleItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center px-4 py-2 text-sm transition-colors ${
                isActive ? 'bg-gray-800 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <span className="mr-3 inline-flex h-7 w-7 items-center justify-center rounded-md bg-gray-800 text-xs font-semibold">
              {item.mark}
            </span>
            {item.label}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}

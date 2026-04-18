import { NavLink } from 'react-router-dom';

const navItems = [
  { to: '/', label: 'Dashboard', mark: 'DB' },
  { to: '/access-settings', label: 'Access Settings', mark: 'AS' },
  { to: '/vlans', label: 'VLANs', mark: 'VL' },
  { to: '/portal-profiles', label: 'Portal Profiles', mark: 'PP' },
  { to: '/users', label: 'Users', mark: 'US' },
  { to: '/vouchers', label: 'Vouchers', mark: 'VO' },
  { to: '/roles', label: 'Roles', mark: 'RO' },
  { to: '/bandwidth-profiles', label: 'Bandwidth', mark: 'BW' },
  { to: '/policies', label: 'Policies', mark: 'PO' },
  { to: '/identity-sources', label: 'Identity Sources', mark: 'ID' },
  { to: '/radius-clients', label: 'RADIUS Clients', mark: 'RC' },
  { to: '/sessions', label: 'Sessions', mark: 'SE' },
  { to: '/alerts', label: 'Alerts', mark: 'AL' },
  { to: '/config-revisions', label: 'Revisions', mark: 'RV' },
  { to: '/backups', label: 'Backups', mark: 'BK' },
  { to: '/ai-recommendations', label: 'AI Insights', mark: 'AI' },
];

export default function Sidebar() {
  return (
    <div className="flex w-64 flex-col bg-gray-950 text-white">
      <div className="border-b border-gray-800 p-4 text-2xl font-bold">AegisNAS</div>
      <nav className="flex-1 overflow-y-auto py-4">
        {navItems.map((item) => (
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

import { useEffect, useState } from 'react';
import api from '../api/client';

type AdminPrincipal = {
  id: number;
  subject: string;
  provider: string;
  display_name: string;
  email: string;
  role: string;
  tenants: string[];
  groups: string[];
  disabled: boolean;
  last_login: string;
};

const roleOptions = ['super_admin', 'ops_admin', 'guest_admin', 'read_only'];

export default function AdminPrincipals() {
  const [items, setItems] = useState<AdminPrincipal[]>([]);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState<number | null>(null);

  const load = async () => {
    try {
      const { data } = await api.get('/admin-principals');
      setItems(data || []);
      setError('');
    } catch (err: any) {
      setError(err?.response?.data || err?.message || 'Failed to load admin principals.');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const updateField = (id: number, field: keyof AdminPrincipal, value: any) => {
    setItems((current) => current.map((item) => (item.id === id ? { ...item, [field]: value } : item)));
  };

  const save = async (item: AdminPrincipal) => {
    setSaving(item.id);
    setError('');
    try {
      await api.put(`/admin-principals/${item.id}`, {
        role: item.role,
        tenants: item.tenants,
        disabled: item.disabled,
      });
      await load();
    } catch (err: any) {
      setError(err?.response?.data || err?.message || 'Failed to save admin principal.');
    } finally {
      setSaving(null);
    }
  };

  return (
    <section className="rounded-lg bg-white p-6 shadow">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Admin Access</h2>
        <p className="mt-1 text-sm text-gray-600">Review delegated admin sessions, assign runtime roles, and scope tenant access for SSO-backed operators.</p>
      </div>
      {error ? <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div> : null}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 text-sm">
          <thead>
            <tr className="text-left text-gray-500">
              <th className="px-3 py-2 font-medium">Subject</th>
              <th className="px-3 py-2 font-medium">Role</th>
              <th className="px-3 py-2 font-medium">Tenants</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Groups</th>
              <th className="px-3 py-2 font-medium">Last Login</th>
              <th className="px-3 py-2 font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {items.map((item) => (
              <tr key={item.id}>
                <td className="px-3 py-3 align-top">
                  <div className="font-medium text-gray-900">{item.display_name || item.subject}</div>
                  <div className="text-xs text-gray-500">{item.subject}</div>
                  {item.email ? <div className="text-xs text-gray-500">{item.email}</div> : null}
                </td>
                <td className="px-3 py-3 align-top">
                  <select
                    value={item.role}
                    onChange={(e) => updateField(item.id, 'role', e.target.value)}
                    className="w-full rounded-md border px-2 py-1"
                  >
                    {roleOptions.map((role) => (
                      <option key={role} value={role}>{role}</option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-3 align-top">
                  <input
                    value={(item.tenants || []).join(', ')}
                    onChange={(e) => updateField(item.id, 'tenants', e.target.value.split(',').map((part) => part.trim()).filter(Boolean))}
                    className="w-full rounded-md border px-2 py-1"
                    placeholder="tenant-a, tenant-b"
                  />
                </td>
                <td className="px-3 py-3 align-top">
                  <label className="inline-flex items-center gap-2 text-gray-700">
                    <input
                      type="checkbox"
                      checked={!item.disabled}
                      onChange={(e) => updateField(item.id, 'disabled', !e.target.checked)}
                    />
                    {item.disabled ? 'Disabled' : 'Active'}
                  </label>
                </td>
                <td className="px-3 py-3 align-top text-xs text-gray-500">
                  {(item.groups || []).length ? (item.groups || []).join(', ') : 'No groups cached'}
                </td>
                <td className="px-3 py-3 align-top text-xs text-gray-500">
                  {item.last_login || 'Never'}
                </td>
                <td className="px-3 py-3 align-top">
                  <button
                    type="button"
                    onClick={() => void save(item)}
                    disabled={saving === item.id}
                    className="rounded-md bg-gray-900 px-3 py-1.5 text-white disabled:opacity-50"
                  >
                    Save
                  </button>
                </td>
              </tr>
            ))}
            {!items.length ? (
              <tr>
                <td className="px-3 py-6 text-sm text-gray-500" colSpan={7}>No admin principals have signed in yet.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}

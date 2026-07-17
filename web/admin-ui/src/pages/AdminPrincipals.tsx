import { useEffect, useState } from 'react';
import api from '../api/client';
import { browserSupportsWebAuthn, createPasskeyCredential } from '../utils/webauthn';

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

type WebAuthnCredential = {
  id: string;
  credential_id_hash: string;
  username_hash: string;
  subject: string;
  display_name?: string;
  credential_name?: string;
  public_key_alg: number;
  sign_count: number;
  transports?: string[];
  enabled: boolean;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
};

const roleOptions = ['super_admin', 'ops_admin', 'guest_admin', 'read_only'];

export default function AdminPrincipals() {
  const [items, setItems] = useState<AdminPrincipal[]>([]);
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([]);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [saving, setSaving] = useState<number | null>(null);
  const [passkeyBusy, setPasskeyBusy] = useState('');
  const [passkeySubject, setPasskeySubject] = useState('');
  const [passkeyLabel, setPasskeyLabel] = useState('Admin passkey');

  const load = async () => {
    try {
      const { data } = await api.get('/admin-principals');
      setItems(data || []);
      setError('');
    } catch (err: any) {
      setError(err?.response?.data || err?.message || 'Failed to load admin principals.');
    }
  };

  const loadPasskeys = async () => {
    try {
      const { data } = await api.get('/system/webauthn?limit=500');
      setCredentials(data?.credentials || []);
    } catch {
      setCredentials([]);
    }
  };

  useEffect(() => {
    void load();
    void loadPasskeys();
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

  const registerPasskey = async () => {
    const subject = passkeySubject.trim();
    if (!subject) {
      setError('Choose an admin subject before registering a passkey.');
      return;
    }
    if (!browserSupportsWebAuthn()) {
      setError('This browser does not support passkeys.');
      return;
    }
    setPasskeyBusy(subject);
    setError('');
    setMessage('');
    try {
      const principal = items.find((item) => item.subject === subject);
      const { data } = await api.post('/system/webauthn/register/options', {
        subject,
        username: subject,
        display_name: principal?.display_name || subject,
        credential_name: passkeyLabel || 'Admin passkey',
      });
      const credential = await createPasskeyCredential(data.publicKey);
      await api.post('/system/webauthn/register/finish', {
        state: data.state,
        credential,
      });
      setMessage(`Passkey registered for ${subject}.`);
      await loadPasskeys();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Passkey registration failed.');
    } finally {
      setPasskeyBusy('');
    }
  };

  const revokePasskey = async (credential: WebAuthnCredential) => {
    setPasskeyBusy(credential.id);
    setError('');
    setMessage('');
    try {
      await api.delete(`/system/webauthn/credentials/${encodeURIComponent(credential.id)}`);
      setMessage(`Passkey revoked for ${credential.subject}.`);
      await loadPasskeys();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Passkey revoke failed.');
    } finally {
      setPasskeyBusy('');
    }
  };

  return (
    <section className="rounded-lg bg-white p-6 shadow">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Admin Access</h2>
        <p className="mt-1 text-sm text-gray-600">Review delegated admin sessions, assign runtime roles, and scope tenant access for SSO-backed operators.</p>
      </div>
      {error ? <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div> : null}
      {message ? <div className="mb-4 rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-700">{message}</div> : null}
      <div className="mb-6 border-b border-gray-200 pb-5">
        <h3 className="text-sm font-semibold text-gray-900">Admin Passkeys</h3>
        <p className="mt-1 text-sm text-gray-600">Enroll phishing-resistant credentials for privileged operators and revoke old authenticators when devices rotate.</p>
        <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <select
            value={passkeySubject}
            onChange={(event) => setPasskeySubject(event.target.value)}
            className="rounded-md border px-3 py-2 text-sm"
          >
            <option value="">Choose admin subject</option>
            {items.map((item) => (
              <option key={item.subject} value={item.subject}>
                {item.display_name || item.subject}
              </option>
            ))}
          </select>
          <input
            value={passkeyLabel}
            onChange={(event) => setPasskeyLabel(event.target.value)}
            className="rounded-md border px-3 py-2 text-sm"
            placeholder="Laptop passkey"
          />
          <button
            type="button"
            onClick={() => void registerPasskey()}
            disabled={Boolean(passkeyBusy)}
            className="rounded-md bg-gray-900 px-4 py-2 text-sm text-white disabled:opacity-50"
          >
            {passkeyBusy && passkeyBusy === passkeySubject ? 'Waiting' : 'Register Passkey'}
          </button>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead>
              <tr className="text-left text-gray-500">
                <th className="px-3 py-2 font-medium">Subject</th>
                <th className="px-3 py-2 font-medium">Credential</th>
                <th className="px-3 py-2 font-medium">Algorithm</th>
                <th className="px-3 py-2 font-medium">Last Used</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {credentials.map((credential) => (
                <tr key={credential.id}>
                  <td className="px-3 py-2">{credential.display_name || credential.subject}</td>
                  <td className="px-3 py-2">
                    <div>{credential.credential_name || 'Passkey'}</div>
                    <div className="text-xs text-gray-500">{credential.credential_id_hash}</div>
                  </td>
                  <td className="px-3 py-2">{credential.public_key_alg}</td>
                  <td className="px-3 py-2 text-xs text-gray-500">{credential.last_used_at || 'Never'}</td>
                  <td className="px-3 py-2">{credential.revoked_at ? 'Revoked' : credential.enabled ? 'Active' : 'Disabled'}</td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => void revokePasskey(credential)}
                      disabled={Boolean(passkeyBusy) || Boolean(credential.revoked_at)}
                      className="rounded-md border px-3 py-1.5 text-xs disabled:opacity-50"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
              {!credentials.length ? (
                <tr>
                  <td className="px-3 py-4 text-sm text-gray-500" colSpan={6}>No admin passkeys have been enrolled yet.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
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

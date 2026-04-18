import { useState } from 'react';
import api from '../api/client';

export default function Backups() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const download = async () => {
    setError('');
    setMessage('');
    try {
      const { data } = await api.get('/backups/config', { responseType: 'blob' });
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'aegisnas-config-backup.json';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('Config JSON backup downloaded.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Download failed.');
    }
  };

  const upload = async () => {
    if (!file) return;
    if (!confirm('Restore this config JSON? A safety revision will be created first.')) return;
    setError('');
    setMessage('');
    try {
      await api.post('/backups/config', await file.text(), { headers: { 'Content-Type': 'application/json' } });
      setMessage('Config JSON restored.');
      window.dispatchEvent(new Event('config-applied'));
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Upload failed.');
    }
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">Backups</h2>
      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-lg bg-white p-6 shadow">
          <h3 className="mb-2 text-lg font-semibold">Download Config</h3>
          <p className="mb-4 text-sm text-gray-600">Export users, vouchers, roles, bandwidth profiles, portal profiles, policies, identity sources, and RADIUS clients as JSON.</p>
          <button onClick={download} className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800">Download JSON</button>
        </section>

        <section className="rounded-lg bg-white p-6 shadow">
          <h3 className="mb-2 text-lg font-semibold">Restore Config</h3>
          <p className="mb-4 text-sm text-gray-600">Upload a JSON backup exported from this page. A rollback revision is created before restore.</p>
          <input type="file" accept="application/json,.json" onChange={(event) => setFile(event.target.files?.[0] ?? null)} className="mb-4 block w-full text-sm" />
          <button disabled={!file} onClick={upload} className="rounded-md bg-amber-700 px-4 py-2 text-white hover:bg-amber-800 disabled:opacity-50">Upload And Restore</button>
        </section>
      </div>
    </div>
  );
}

import { useEffect, useState } from 'react';
import api from '../api/client';

export default function ConfigRevisions() {
  const [revisions, setRevisions] = useState<any[]>([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const fetchRevisions = async () => {
    try {
      const { data } = await api.get('/config-revisions');
      setRevisions(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load revisions.');
    }
  };

  useEffect(() => {
    fetchRevisions();
  }, []);

  const rollback = async (revision: number) => {
    if (!confirm(`Rollback to revision ${revision}? A safety snapshot will be created first.`)) return;
    setError('');
    setMessage('');
    try {
      await api.post(`/config/rollback/${revision}`);
      setMessage(`Rollback to revision ${revision} completed.`);
      window.dispatchEvent(new Event('config-applied'));
      await fetchRevisions();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Rollback failed.');
    }
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">Config Revisions</h2>
      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      <div className="overflow-x-auto rounded-lg bg-white shadow">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {['Revision', 'Checksum', 'Created By', 'Created At', 'Actions'].map((label) => (
                <th key={label} className="px-5 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {revisions.map((revision) => (
              <tr key={revision.id}>
                <td className="px-5 py-4 text-sm">{revision.revision}</td>
                <td className="max-w-sm truncate px-5 py-4 font-mono text-xs">{revision.checksum}</td>
                <td className="px-5 py-4 text-sm">{revision.created_by}</td>
                <td className="px-5 py-4 text-sm">{revision.created_at}</td>
                <td className="px-5 py-4 text-sm">
                  <button onClick={() => rollback(revision.revision)} className="text-sky-700 hover:text-sky-900">Rollback</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

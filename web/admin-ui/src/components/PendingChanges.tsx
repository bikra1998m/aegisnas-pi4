import { useEffect, useState } from 'react';
import api from '../api/client';

export default function PendingChanges() {
  const [count, setCount] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const refresh = async () => {
    try {
      const { data } = await api.get('/staged-changes');
      setCount(Array.isArray(data) ? data.length : 0);
    } catch {
      setCount(0);
    }
  };

  useEffect(() => {
    refresh();
    const handler = () => refresh();
    window.addEventListener('staged-changes-updated', handler);
    return () => window.removeEventListener('staged-changes-updated', handler);
  }, []);

  const validate = async () => {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.post('/validate');
      setMessage(`Validation passed for ${data.changes ?? count} staged change(s).`);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Validation failed.');
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.post('/apply');
      setMessage(`Applied ${data.changes ?? count} change(s).`);
      await refresh();
      window.dispatchEvent(new Event('config-applied'));
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Apply failed.');
    } finally {
      setBusy(false);
    }
  };

  if (count === 0 && !message && !error) return null;

  return (
    <div className="border-b border-amber-200 bg-amber-50 px-6 py-3 text-sm text-amber-950">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          {count > 0 ? <strong>{count} pending staged change(s).</strong> : <strong>No pending staged changes.</strong>}
          {message && <span className="ml-2 text-emerald-700">{message}</span>}
          {error && <span className="ml-2 text-red-700">{String(error)}</span>}
        </div>
        {count > 0 && (
          <div className="flex gap-2">
            <button disabled={busy} onClick={validate} className="rounded-md border border-amber-400 px-3 py-1 hover:bg-amber-100 disabled:opacity-50">
              Validate
            </button>
            <button disabled={busy} onClick={apply} className="rounded-md bg-amber-700 px-3 py-1 text-white hover:bg-amber-800 disabled:opacity-50">
              Apply
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

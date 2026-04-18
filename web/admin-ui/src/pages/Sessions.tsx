import { useEffect, useState } from 'react';
import api from '../api/client';

export default function Sessions() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchSessions = async () => {
    setError('');
    try {
      const { data } = await api.get('/sessions');
      setSessions(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load sessions.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
    const interval = window.setInterval(fetchSessions, 10000);
    return () => window.clearInterval(interval);
  }, []);

  const terminateSession = async (id: string) => {
    if (!confirm('Terminate this session?')) return;
    await api.delete(`/sessions/${id}`);
    await fetchSessions();
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">Sessions</h2>
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      <div className="overflow-x-auto rounded-lg bg-white shadow">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {['User', 'IP', 'MAC', 'Auth', 'VLAN', 'Started', 'Status', 'Traffic', 'Actions'].map((label) => (
                <th key={label} className="px-5 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={9}>Loading...</td></tr>
            ) : sessions.length === 0 ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={9}>No sessions found.</td></tr>
            ) : (
              sessions.map((session) => (
                <tr key={session.id}>
                  <td className="px-5 py-4 text-sm">{session.username}</td>
                  <td className="px-5 py-4 text-sm">{session.ip}</td>
                  <td className="px-5 py-4 text-sm">{session.mac}</td>
                  <td className="px-5 py-4 text-sm">{session.auth_method}</td>
                  <td className="px-5 py-4 text-sm">{session.vlan}</td>
                  <td className="px-5 py-4 text-sm">{session.start_time}</td>
                  <td className="px-5 py-4 text-sm">{session.end_time ? 'Ended' : 'Active'}</td>
                  <td className="px-5 py-4 text-sm">{Number(session.bytes_in || 0) + Number(session.bytes_out || 0)} bytes</td>
                  <td className="px-5 py-4 text-sm">
                    {!session.end_time && (
                      <button onClick={() => terminateSession(session.id)} className="text-red-700 hover:text-red-900">
                        Terminate
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

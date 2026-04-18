import { useEffect, useState } from 'react';
import api from '../api/client';

export default function Alerts() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [error, setError] = useState('');

  const fetchAlerts = async () => {
    try {
      const { data } = await api.get('/alerts');
      setAlerts(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load alerts.');
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const acknowledge = async (id: number) => {
    await api.post(`/alerts/${id}/acknowledge`);
    await fetchAlerts();
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">Alerts</h2>
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      <div className="space-y-3">
        {alerts.length === 0 ? (
          <div className="rounded-lg bg-white p-6 text-gray-500 shadow">No alerts found.</div>
        ) : (
          alerts.map((alert) => (
            <div key={alert.id} className="rounded-lg bg-white p-4 shadow">
              <div className="flex flex-wrap justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold uppercase text-gray-500">{alert.severity} from {alert.source}</div>
                  <div className="text-lg font-semibold text-gray-900">{alert.message}</div>
                  <p className="mt-1 text-sm text-gray-600">{alert.details}</p>
                  <p className="mt-2 text-xs text-gray-500">{alert.created_at}</p>
                </div>
                {!alert.acknowledged && (
                  <button onClick={() => acknowledge(alert.id)} className="h-9 rounded-md bg-sky-700 px-3 text-white hover:bg-sky-800">
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

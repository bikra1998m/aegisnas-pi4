import { useEffect, useState } from 'react';
import api from '../api/client';

export default function AIRecommendations() {
  const [items, setItems] = useState<any[]>([]);
  const [error, setError] = useState('');

  const fetchItems = async () => {
    try {
      const { data } = await api.get('/ai-recommendations');
      setItems(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load recommendations.');
    }
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const acknowledge = async (id: number) => {
    await api.post(`/ai-recommendations/${id}/acknowledge`);
    await fetchItems();
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">AI Recommendations</h2>
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      <div className="space-y-3">
        {items.length === 0 ? (
          <div className="rounded-lg bg-white p-6 text-gray-500 shadow">No recommendations found.</div>
        ) : (
          items.map((item) => (
            <div key={item.id} className="rounded-lg bg-white p-4 shadow">
              <div className="flex flex-wrap justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold uppercase text-gray-500">
                    {item.severity} from {item.source} - confidence {Math.round(Number(item.confidence || 0) * 100)}%
                  </div>
                  <div className="text-lg font-semibold text-gray-900">{item.title}</div>
                  <p className="mt-1 text-sm text-gray-600">{item.description}</p>
                  <p className="mt-2 text-sm font-medium text-gray-800">{item.remediation}</p>
                  <p className="mt-2 text-xs text-gray-500">{item.created_at}</p>
                </div>
                {!item.acknowledged && (
                  <button onClick={() => acknowledge(item.id)} className="h-9 rounded-md bg-sky-700 px-3 text-white hover:bg-sky-800">
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

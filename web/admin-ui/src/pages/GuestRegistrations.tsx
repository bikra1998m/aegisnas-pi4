import { useEffect, useState } from 'react';
import api from '../api/client';

export default function GuestRegistrations() {
  const [records, setRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchRecords = async () => {
    try {
      setError('');
      const { data } = await api.get('/guest-registrations');
      setRecords(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load guest registrations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecords();
    const interval = window.setInterval(fetchRecords, 10000);
    return () => window.clearInterval(interval);
  }, []);

  const approve = async (id: string) => {
    if (!confirm('Approve this guest request?')) return;
    await api.post(`/guest-registrations/${id}/approve`);
    await fetchRecords();
  };

  const reject = async (id: string) => {
    const reason = window.prompt('Reject reason (optional):', '') ?? '';
    if (!confirm('Reject this guest request?')) return;
    await api.post(`/guest-registrations/${id}/reject`, { reason });
    await fetchRecords();
  };

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Guest Registrations</h2>
          <p className="mt-1 text-sm text-gray-600">Track self-registration, sponsor approval, and delivery outcomes.</p>
        </div>
      </div>
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      <div className="overflow-x-auto rounded-lg bg-white shadow">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {['Guest', 'Contact', 'Sponsor', 'Status', 'Delivery', 'Created', 'Actions'].map((label) => (
                <th key={label} className="px-5 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={7}>Loading...</td></tr>
            ) : records.length === 0 ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={7}>No guest registrations found.</td></tr>
            ) : (
              records.map((record) => (
                <tr key={record.id}>
                  <td className="px-5 py-4 text-sm">
                    <div className="font-semibold text-gray-900">{record.full_name}</div>
                    <div className="text-xs text-gray-500">{record.company || 'No company'}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div>{record.email || 'No email'}</div>
                    <div className="text-xs text-gray-500">{record.phone || 'No phone'}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div>{record.sponsor_name || 'No sponsor name'}</div>
                    <div className="text-xs text-gray-500">{record.sponsor_email || record.sponsor_phone || 'No sponsor contact'}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div className="font-medium text-gray-900">{record.status}</div>
                    {record.rejection_reason && <div className="text-xs text-red-700">{record.rejection_reason}</div>}
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div>Approval: {record.approval_delivery_status || 'n/a'}</div>
                    <div>Invite: {record.invite_delivery_status || 'n/a'}</div>
                    {(record.approval_delivery_error || record.invite_delivery_error) && (
                      <div className="mt-1 text-xs text-red-700">{record.approval_delivery_error || record.invite_delivery_error}</div>
                    )}
                  </td>
                  <td className="px-5 py-4 text-sm text-gray-600">{record.created_at}</td>
                  <td className="px-5 py-4 text-sm">
                    {record.status === 'pending' ? (
                      <div className="flex flex-wrap gap-2">
                        <button onClick={() => approve(record.id)} className="rounded-md bg-sky-700 px-3 py-1.5 text-white hover:bg-sky-800">
                          Approve
                        </button>
                        <button onClick={() => reject(record.id)} className="rounded-md bg-red-700 px-3 py-1.5 text-white hover:bg-red-800">
                          Reject
                        </button>
                      </div>
                    ) : (
                      <span className="text-gray-500">No action</span>
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

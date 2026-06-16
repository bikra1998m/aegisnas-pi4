import { useEffect, useState } from 'react';
import api from '../api/client';

export default function Devices() {
  const [devices, setDevices] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchDevices = async () => {
    try {
      setError('');
      const { data } = await api.get('/devices');
      setDevices(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load devices.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = window.setInterval(fetchDevices, 15000);
    return () => window.clearInterval(interval);
  }, []);

  const downloadCertificate = async (device: any) => {
    if (!device.certificate_id) return;
    const { data } = await api.get(`/devices/${device.certificate_id}/certificate`, {
      responseType: 'blob',
    });
    const blob = new Blob([data], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${device.username || 'device'}-${device.mac}.pem`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Devices</h2>
        <p className="mt-1 text-sm text-gray-600">Inventory, passive fingerprints, compliance state, and onboarding certificates.</p>
      </div>
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      <div className="overflow-x-auto rounded-lg bg-white shadow">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {['Device', 'User', 'Platform', 'Profile', 'Risk', 'Compliance', 'Managed', 'Last Seen', 'Actions'].map((label) => (
                <th key={label} className="px-5 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={9}>Loading...</td></tr>
            ) : devices.length === 0 ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={9}>No devices found.</td></tr>
            ) : (
              devices.map((device) => (
                <tr key={device.id}>
                  <td className="px-5 py-4 text-sm">
                    <div className="font-semibold text-gray-900">{device.friendly_name || device.mac}</div>
                    <div className="text-xs text-gray-500">{device.mac}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div>{device.username || 'Unknown'}</div>
                    <div className="text-xs text-gray-500">{device.ownership || 'Unspecified ownership'}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div>{device.platform || 'Unknown'}</div>
                    <div className="text-xs text-gray-500">{device.device_type || 'Unknown type'}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div>{device.hostname || 'No hostname'}</div>
                    <div className="text-xs text-gray-500">
                      {device.dhcp_client_id || device.mac_oui || 'No DHCP fingerprint'}
                    </div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div className="font-medium text-gray-900">{device.risk_score ?? 0}</div>
                    <div className="text-xs text-gray-500">
                      {Array.isArray(device.risk_reasons) && device.risk_reasons.length > 0
                        ? device.risk_reasons.join(', ')
                        : 'No risk reasons'}
                    </div>
                  </td>
                  <td className="px-5 py-4 text-sm">
                    <div className="font-medium text-gray-900">{device.compliance_status || 'unknown'}</div>
                    <div className="text-xs text-gray-500">{device.remediation_state || 'No remediation state'}</div>
                  </td>
                  <td className="px-5 py-4 text-sm">{device.managed ? 'Yes' : 'No'}</td>
                  <td className="px-5 py-4 text-sm text-gray-600">{device.last_seen || device.created_at}</td>
                  <td className="px-5 py-4 text-sm">
                    {device.certificate_id ? (
                      <button onClick={() => downloadCertificate(device)} className="text-sky-700 hover:text-sky-900">
                        Download certificate
                      </button>
                    ) : (
                      <span className="text-gray-500">No certificate</span>
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

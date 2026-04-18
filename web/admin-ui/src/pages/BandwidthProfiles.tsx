import CrudPage from '../components/CrudPage';

export default function BandwidthProfiles() {
  return (
    <CrudPage
      title="Bandwidth Profiles"
      endpoint="/bandwidth-profiles"
      itemName="Bandwidth Profile"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'download_rate_kbps', label: 'Download Kbps' },
        { key: 'upload_rate_kbps', label: 'Upload Kbps' },
        { key: 'burst_kb', label: 'Burst KB' },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'download_rate_kbps', label: 'Download Rate Kbps', type: 'number', required: true },
        { name: 'upload_rate_kbps', label: 'Upload Rate Kbps', type: 'number', required: true },
        { name: 'burst_kb', label: 'Burst KB', type: 'number', defaultValue: 0 },
      ]}
    />
  );
}

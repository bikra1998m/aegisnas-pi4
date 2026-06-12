import CrudPage from '../components/CrudPage';

export default function RadiusClients() {
  return (
    <CrudPage
      title="RADIUS Clients"
      endpoint="/radius-clients"
      itemName="RADIUS client"
      columns={[
        { key: 'shortname', label: 'Short Name' },
        { key: 'ip', label: 'IP Address' },
        { key: 'nas_type', label: 'NAS Type / Vendor' },
        { key: 'description', label: 'Description' },
        {
          key: 'enabled',
          label: 'Enabled',
          render: (item) => (item.enabled ? 'Yes' : 'No'),
        },
      ]}
      fields={[
        { name: 'shortname', label: 'Short Name', required: true },
        { name: 'ip', label: 'IP Address', required: true, placeholder: '10.20.0.2' },
        { name: 'secret', label: 'Shared Secret', type: 'password', required: true },
        { name: 'nas_type', label: 'NAS Type / Vendor Profile', placeholder: 'other, aruba, cisco, mikrotik, ubnt' },
        { name: 'description', label: 'Description', type: 'textarea' },
        { name: 'enabled', label: 'Enabled', type: 'checkbox', defaultValue: true },
      ]}
    />
  );
}

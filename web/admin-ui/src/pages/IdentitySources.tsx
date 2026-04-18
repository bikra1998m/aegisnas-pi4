import CrudPage from '../components/CrudPage';

export default function IdentitySources() {
  return (
    <CrudPage
      title="Identity Sources"
      endpoint="/identity-sources"
      itemName="Identity Source"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'enabled', label: 'Enabled', render: (item) => (item.enabled ? 'Yes' : 'No') },
        { key: 'priority', label: 'Priority' },
        { key: 'config', label: 'Config', render: (item) => <code>{JSON.stringify(item.config ?? {})}</code> },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'type', label: 'Type', required: true, defaultValue: 'local' },
        { name: 'enabled', label: 'Enabled', type: 'checkbox', defaultValue: true },
        { name: 'priority', label: 'Priority', type: 'number', defaultValue: 10 },
        { name: 'config', label: 'Config JSON', type: 'json', defaultValue: '{}' },
      ]}
    />
  );
}

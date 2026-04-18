import CrudPage from '../components/CrudPage';

export default function VLANs() {
  return (
    <CrudPage
      title="VLANs"
      endpoint="/vlans"
      itemName="VLAN"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'vlan', label: 'VLAN ID' },
        { key: 'description', label: 'Description' },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'vlan', label: 'VLAN ID', type: 'number', required: true },
        { name: 'description', label: 'Description' },
      ]}
    />
  );
}

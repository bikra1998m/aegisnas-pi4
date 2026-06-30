import CrudPage from '../components/CrudPage';

export default function Roles() {
  return (
    <CrudPage
      title="Roles"
      endpoint="/roles"
      itemName="Role"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'vlan', label: 'VLAN' },
        { key: 'bandwidth_profile', label: 'Bandwidth' },
        { key: 'acl_policy_name', label: 'ACL Policy' },
        { key: 'session_timeout', label: 'Session Timeout' },
        { key: 'idle_timeout', label: 'Idle Timeout' },
        { key: 'priority', label: 'Priority' },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'description', label: 'Description' },
        { name: 'vlan', label: 'VLAN', type: 'number' },
        { name: 'bandwidth_profile', label: 'Bandwidth Profile' },
        { name: 'session_timeout', label: 'Session Timeout Seconds', type: 'number' },
        { name: 'idle_timeout', label: 'Idle Timeout Seconds', type: 'number' },
        { name: 'portal_profile', label: 'Portal Profile' },
        { name: 'acl_policy_name', label: 'ACL Policy Name' },
        { name: 'priority', label: 'Priority', type: 'number', defaultValue: 0 },
      ]}
    />
  );
}

import CrudPage from '../components/CrudPage';

const compactJSON = (value: unknown) => JSON.stringify(value ?? {}, null, 0);

export default function Policies() {
  return (
    <CrudPage
      title="Policies"
      endpoint="/policies"
      itemName="Policy"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'priority', label: 'Priority' },
        { key: 'enabled', label: 'Enabled', render: (item) => (item.enabled ? 'Yes' : 'No') },
        { key: 'match_conditions', label: 'Match', render: (item) => <code>{compactJSON(item.match_conditions)}</code> },
        { key: 'action', label: 'Action' },
        { key: 'vlan', label: 'VLAN' },
        { key: 'acl_policy_name', label: 'ACL Policy' },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'description', label: 'Description' },
        { name: 'priority', label: 'Priority', type: 'number', defaultValue: 0 },
        { name: 'enabled', label: 'Enabled', type: 'checkbox', defaultValue: true },
        { name: 'match_conditions', label: 'Match Conditions JSON', type: 'json', required: true, defaultValue: '{\n  "authenticated": true\n}' },
        { name: 'action', label: 'Action', required: true, defaultValue: 'allow' },
        { name: 'vlan', label: 'VLAN', type: 'number' },
        { name: 'bandwidth_profile', label: 'Bandwidth Profile' },
        { name: 'session_timeout', label: 'Session Timeout Seconds', type: 'number' },
        { name: 'idle_timeout', label: 'Idle Timeout Seconds', type: 'number' },
        { name: 'portal_profile', label: 'Portal Profile' },
        { name: 'acl_policy_name', label: 'ACL Policy Name' },
        { name: 'quarantine', label: 'Quarantine', type: 'checkbox' },
      ]}
    />
  );
}
